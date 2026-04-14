from typing import List
import cv2
import numpy as np
from pyzbar.pyzbar import decode
import logging


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
    """
    Reads an image from a file path and passes it to the processor.
    Bridges the gap between the Tkinter GUI upload button and the CV2 scanner.
    """
    image = cv2.imread(filepath)
    if image is None:
        logging.error(f"Could not read image at {filepath}. File may be corrupted or missing.")
        return []

    # Pass the loaded image to the main processing function
    return process_image(image, "Uploaded QR Image")


def scan_webcam_and_return() -> List[str]:
    """Called by app.py to turn on the webcam, scan once, and return the result."""
    cap = cv2.VideoCapture(0)
    payloads = []

    while True:
        success, frame = cap.read()
        if not success:
            break

        # 1. Decode the frame in real-time
        decoded_objects = decode(frame)

        # 2. Draw the dynamic bounding box over the live feed
        for obj in decoded_objects:
            # Draw a green box around the QR code
            points = obj.polygon
            if len(points) == 4:
                pts = np.array([(val.x, val.y) for val in points], dtype=np.int32)
                cv2.polylines(frame, [pts], True, (0, 255, 0), 3)

            # Overlay the payload text
            rect = obj.rect
            payload = obj.data.decode('utf-8')
            cv2.putText(frame, payload, (rect.left, rect.top - 10),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)

        # 3. Show the modified frame (with the green box) to the user
        cv2.imshow("Webcam - Press 'q' to scan", frame)

        # 4. If 'q' is pressed, save the payloads currently in frame and exit
        if cv2.waitKey(1) & 0xFF == ord('q'):
            payloads = [obj.data.decode('utf-8') for obj in decoded_objects]
            break

    cap.release()
    cv2.destroyAllWindows()
    return payloads