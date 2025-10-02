from typing import Union
# TODO: make a padding function

def open_file_as_bytes(filename: str) -> Union[bytes, None]:
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except FileNotFoundError as e:
        print(f"File Not Found: {e}")
        return None
