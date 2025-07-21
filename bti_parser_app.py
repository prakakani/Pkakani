import streamlit as st
import pandas as pd

FIELD_DEFINITIONS = [
    {"Field Name": "ND5FDBID", "Offset": "000", "Length": 2, "Type": "BIT(16)", "Description": "Record ID = X'D5FD'"},
    {"Field Name": "ND5FDCHK", "Offset": "002", "Length": 1, "Type": "BIT(8)", "Description": "Record Code Check"},
    {"Field Name": "ND5FDPGM", "Offset": "004", "Length": 4, "Type": "DCHAR(4)", "Description": "Last Program to File"},
    {"Field Name": "ND5FDTYP", "Offset": "020", "Length": 3, "Type": "DCHAR(3)", "Description": "BARTS Record Type"},
    {"Field Name": "ND5FDNBC", "Offset": "026", "Length": 2, "Type": "DCHAR(2)", "Description": "Total Number of Blocks"},
    {"Field Name": "ND5FDTCI", "Offset": "05E", "Length": 2, "Type": "BIT(16)", "Description": "Itinerary Segment Count"},
]

def hex_to_ascii(hex_str):
    try:
        return bytes.fromhex(hex_str).decode('cp037', errors='replace')
    except:
        return ""

def parse_hex_dump(hex_input):
    hex_lines = hex_input.splitlines()
    hex_data = ""
    for line in hex_lines:
        if "**" in line:
            hex_part = line.split("**")[0].strip()
            hex_data += hex_part.replace(" ", "")
    parsed = []
    for field in FIELD_DEFINITIONS:
        offset = int(field["Offset"], 16) * 2
        length = field["Length"] * 2
        hex_value = hex_data[offset:offset+length]
        ascii_value = hex_to_ascii(hex_value)
        parsed.append({
            "Field Name": field["Field Name"],
            "Offset": field["Offset"],
            "Length": field["Length"],
            "Hex Value": hex_value,
            "ASCII Value": ascii_value,
            "Description": field["Description"]
        })
    return pd.DataFrame(parsed)

st.title("BTI D5FD Record Parser")

hex_input = st.text_area("Paste BTI Hex Dump", height=300)

if st.button("Parse"):
    if hex_input.strip():
        df = parse_hex_dump(hex_input)
        st.dataframe(df)
        st.download_button("Download CSV", df.to_csv(index=False), "parsed_bti.csv", "text/csv")
        st.download_button("Download JSON", df.to_json(orient="records", indent=2), "parsed_bti.json", "application/json")
    else:
        st.warning("Please paste a valid hex dump.")
