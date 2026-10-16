/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

const CAMERA_KEY = 'totp-vault-camera';
const SCAN_INTERVAL_MS = 150;
// Lenses that can't focus on a QR code held close, or that point the wrong
// way. They're skipped when no camera has been picked yet.
const POOR_LENS = /ultra|tele|depth|infrared|front|facetime/i;
const REAR_LENS = /back|rear|environment/i;

let jsQRPromise = null;
let detectorPromise = null;

function loadJsQR() {
  jsQRPromise ??= new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = 'vendor/jsQR.js';
    script.onload = () => resolve(window.jsQR);
    script.onerror = () => {
      jsQRPromise = null;
      reject(new Error('Couldn’t load the QR decoder.'));
    };
    document.head.append(script);
  });
  return jsQRPromise;
}

async function createDetector() {
  if ('BarcodeDetector' in window) {
    try {
      const formats = await BarcodeDetector.getSupportedFormats();
      if (formats.includes('qr_code')) {
        const detector = new BarcodeDetector({ formats: ['qr_code'] });
        return async (source) =>
          (await detector.detect(source))[0]?.rawValue ?? null;
      }
    } catch {
      // Fall back to jsQR.
    }
  }
  const jsQR = await loadJsQR();
  const canvas = document.createElement('canvas');
  const context = canvas.getContext('2d', { willReadFrequently: true });
  return async (source, { thorough = false } = {}) => {
    const width = source.videoWidth ?? source.width;
    const height = source.videoHeight ?? source.height;
    if (!width || !height) {
      return null;
    }
    // Smaller frames keep live scanning fast; still images get more pixels.
    const scale = Math.min(
      1,
      (thorough ? 2048 : 800) / Math.max(width, height),
    );
    canvas.width = Math.round(width * scale);
    canvas.height = Math.round(height * scale);
    context.drawImage(source, 0, 0, canvas.width, canvas.height);
    const { data } = context.getImageData(0, 0, canvas.width, canvas.height);
    return (
      jsQR(data, canvas.width, canvas.height, {
        inversionAttempts: thorough ? 'attemptBoth' : 'dontInvert',
      })?.data ?? null
    );
  };
}

function getDetector() {
  detectorPromise ??= createDetector();
  return detectorPromise;
}

function savedCamera() {
  try {
    return localStorage.getItem(CAMERA_KEY);
  } catch {
    return null;
  }
}

export function saveCamera(deviceId) {
  try {
    localStorage.setItem(CAMERA_KEY, deviceId);
  } catch {
    // Not remembering the camera is fine.
  }
}

/** Reads a QR code from an image `File` or `Blob`. */
export async function scanImage(blob) {
  const detect = await getDetector();
  const bitmap = await createImageBitmap(blob);
  try {
    return await detect(bitmap, { thorough: true });
  } finally {
    bitmap.close();
  }
}

/**
 * Streams a camera into `video` and calls `onResult(text)` for each QR code
 * found until it returns `true`.
 */
export class Scanner {
  #video;
  #onResult;
  #stream = null;

  constructor(video, onResult) {
    this.#video = video;
    this.#onResult = onResult;
  }

  /**
   * Starts `deviceId`, the saved camera, or a rear camera, in that order.
   * Returns the available cameras and the ID of the one in use.
   */
  async start(deviceId = savedCamera(), { picked = Boolean(deviceId) } = {}) {
    this.stop();
    const constraints = {
      width: { ideal: 1280 },
      height: { ideal: 720 },
      ...(deviceId
        ? { deviceId: { exact: deviceId } }
        : { facingMode: { ideal: 'environment' } }),
    };
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: constraints,
      });
    } catch (error) {
      // The saved camera is gone, for example an unplugged webcam.
      if (deviceId && error.name === 'OverconstrainedError') {
        return this.start(null, { picked: false });
      }
      throw error;
    }
    const track = stream.getVideoTracks()[0];
    const current = track.getSettings().deviceId;
    // Camera labels are only readable once permission is granted.
    const cameras = (await navigator.mediaDevices.enumerateDevices()).filter(
      (device) => device.kind === 'videoinput',
    );
    if (!picked && POOR_LENS.test(track.label)) {
      const main = cameras.find(
        ({ label }) => REAR_LENS.test(label) && !POOR_LENS.test(label),
      );
      if (main && main.deviceId !== current) {
        stream.getTracks().forEach((other) => other.stop());
        return this.start(main.deviceId, { picked: true });
      }
    }
    this.#stream = stream;
    track
      .applyConstraints({ advanced: [{ focusMode: 'continuous' }] })
      .catch(() => {});
    this.#video.srcObject = stream;
    await this.#video.play();
    this.#scan(stream);
    return { cameras, current };
  }

  stop() {
    this.#stream?.getTracks().forEach((track) => track.stop());
    this.#stream = null;
    this.#video.srcObject = null;
  }

  async #scan(stream) {
    const detect = await getDetector();
    while (this.#stream === stream) {
      if (this.#video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) {
        try {
          const text = await detect(this.#video);
          if (text && this.#stream === stream && this.#onResult(text)) {
            this.stop();
            return;
          }
        } catch {
          // A frame that fails to decode is not an error worth reporting.
        }
      }
      await new Promise((resolve) => setTimeout(resolve, SCAN_INTERVAL_MS));
    }
  }
}
