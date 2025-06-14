import pefile
import joblib
import pandas as pd
import os

def extract_features(file_path):
    try:
        pe = pefile.PE(file_path)

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
            'BaseOfData': pe.OPTIONAL_HEADER.BaseOfData if hasattr(pe.OPTIONAL_HEADER, 'BaseOfData') else 0,
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
            'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        }

        return headers
    except pefile.PEFormatError as e:
        raise Exception(f"Invalid PE file format: {str(e)}")
    except Exception as e:
        raise Exception(f"Error processing file: {str(e)}")

def detect_ransomware(file_path):
    try:
        # Extract features
        features = extract_features(file_path)
        if not features:
            return "Error: Could not extract features from file"
        
        # Create DataFrame
        df = pd.DataFrame([features])
        
        # Load the trained model
        model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models', 'ransomware_model.pkl')
        model = joblib.load(model_path)
        
        # Make prediction
        prediction = model.predict(df)[0]
        
        return "Ransomware detected!" if prediction == 1 else "File appears to be legitimate"
    
    except Exception as e:
        return f"Error during detection: {str(e)}"