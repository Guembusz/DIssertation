import cv2
import os
import numpy as np
from pyzbar.pyzbar import decode
from typing import List


def process_image(image: np.ndarray, window_name: str = "QR Scanner") -> List[str]:
    """Decodes QR codes in a given image/frame, draws overlays, and returns payloads."""
    decoded_objects = decode(image)
    payloads = []

    for obj in decoded_objects:
        payload = obj.data.decode('utf-8')
        payloads.append(payload)

        # Draw a green box around the QR code
        points = obj.polygon
        if len(points) == 4:
            pts = np.array([(val.x, val.y) for val in points], dtype=np.int32)
            cv2.polylines(image, [pts], True, (0, 255, 0), 3)

        rect = obj.rect
        cv2.putText(image, payload, (rect.left, rect.top - 10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)

    cv2.imshow(window_name, image)
    return payloads


def process_image_file(filepath: str) -> List[str]:
    """Called by app.py to scan a static image and return the results."""
    if not os.path.exists(filepath):
        return []

    image = cv2.imread(filepath)
    if image is None:
        return []

    payloads = process_image(image, "Static Image Scan")
    cv2.waitKey(0)
    cv2.destroyAllWindows()
    return payloads


def scan_webcam_and_return() -> List[str]:
    """Called by app.py to turn on the webcam, scan once, and return the result."""
    cap = cv2.VideoCapture(0)
    payloads = []

    while True:
        success, frame = cap.read()
        if not success:
            break

        cv2.imshow("Webcam - Press 'q' to scan", frame)

        if cv2.waitKey(1) & 0xFF == ord('q'):
            payloads = process_image(frame, "Captured Frame")
            break

    cap.release()
    cv2.destroyAllWindows()
    return payloads