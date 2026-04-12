import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import scanner
import analyzer


class QRSecurityApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure QR Sandbox - Enterprise Edition")
        self.root.geometry("650x450")

        # Configure layout
        self.root.grid_columnconfigure(0, weight=1)

        # UI Header
        tk.Label(root, text="QR Code Security Scanner", font=("Arial", 22, "bold")).pack(pady=20)

        # Status Display Box
        self.status_label = tk.Label(root, text="AWAITING SCAN", font=("Arial", 24, "bold"),
                                     bg="grey", fg="white", width=25, pady=15)
        self.status_label.pack(pady=10)

        # Message/Reason Box
        self.message_label = tk.Label(root, text="Please scan a live webcam feed or upload an image.",
                                      font=("Arial", 12), wraplength=550)
        self.message_label.pack(pady=20)

        # Buttons Frame
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=20)

        self.webcam_btn = tk.Button(btn_frame, text="Scan via Webcam", font=("Arial", 14),
                                    command=self.run_webcam_scan, width=18)
        self.webcam_btn.grid(row=0, column=0, padx=15)

        self.upload_btn = tk.Button(btn_frame, text="Upload .PNG/.JPG", font=("Arial", 14),
                                    command=self.run_image_scan, width=18)
        self.upload_btn.grid(row=0, column=1, padx=15)

    def process_payloads(self, payloads: list):
        if not payloads:
            self.update_ui("NO QR FOUND", "grey", "Could not detect a QR code in the image/feed.")
            return

        # Disable buttons while analyzing
        self.webcam_btn.config(state=tk.DISABLED)
        self.upload_btn.config(state=tk.DISABLED)

        # Set UI to processing state
        self.update_ui("ANALYZING...", "#f1c40f", "Querying Threat Intelligence APIs...")

        # Run analysis in a background thread to prevent GUI freezing
        target_payload = payloads[0]
        threading.Thread(target=self._run_analysis_thread, args=(target_payload,), daemon=True).start()

    def _run_analysis_thread(self, payload: str):
        """Executes the heavy network/security checks in the background."""
        result = analyzer.analyze_qr_data(payload)

        # Safely update the Tkinter UI from the background thread using .after()
        self.root.after(0, self.update_ui, result.status, result.level.value, result.message)
        self.root.after(0, self.webcam_btn.config, {"state": tk.NORMAL})
        self.root.after(0, self.upload_btn.config, {"state": tk.NORMAL})



    def update_ui(self, status: str, color: str, message: str):
        """Thread-safe UI updater."""
        self.status_label.config(text=status, bg=color)
        self.message_label.config(text=message)

    def run_image_scan(self):
        filepath = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg")])
        if filepath:
            payloads = scanner.process_image_file(filepath)
            self.process_payloads(payloads)



    def run_webcam_scan(self):
        messagebox.showinfo("Webcam Scan",
                            "Press 'q' on your keyboard to capture the frame and run the security check.")
        payloads = scanner.scan_webcam_and_return()
        self.process_payloads(payloads)


if __name__ == "__main__":
    root = tk.Tk()
    app = QRSecurityApp(root)
    root.mainloop()