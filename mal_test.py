import pefile
import joblib
import pandas as pd

def extract_pe_headers(filepath):
    try:
        pe = pefile.PE(filepath)

        # Extract PE headers
        headers = {
            'Machine': pe.FILE_HEADER.Machine,
            'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
            'Characteristics': pe.FILE_HEADER.Characteristics,
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
            'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
            'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
            'BaseOfData': pe.OPTIONAL_HEADER.BaseOfData,
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
            'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        }

        return headers
    except pefile.PEFormatError as e:
        print(f"Error: Invalid PE file format - {e}")
        return None

model = joblib.load('malware_model.pkl')

file_path = 'Photoshop_Set-Up.exe' 

pe_headers = extract_pe_headers(file_path)
def res():
    if pe_headers:
        df = pd.DataFrame([pe_headers])  
        prediction = model.predict(df)[0]  
        return prediction

    # if prediction == 1:
    #     print(f"The file '{file_path}' is classified as malware.")
    # else:
    #     print(f"The file '{file_path}' is classified as legitimate.")
