import streamlit as st
import pandas as pd

# Define the BTI D5FD field mapping (Field Name, Offset, Length)
FIELD_DEFINITIONS = [
    ("ND5FDBID", "000", 2),
    ("ND5FDCHK", "002", 1),
    ("ND5FDPGM", "004", 4),
    ("ND5FDFCH", "008", 4),
    ("ND5FDBCH", "00C", 4),
    ("ND5FDTYP", "020", 3),
    ("ND5FDETK", "023", 1),
    ("ND5FDBNC", "024", 2),
    ("ND5FDNBC", "026", 2),
    ("ND5FDSN1", "028", 2),
    ("ND5FDSN2", "02A", 2),
    ("ND5FDNAB", "02C", 2),
    ("ND5FDCIR", "02E", 2),
    ("ND5FDRTI", "030", 1),
    ("ND5FDEXT", "031", 1),
    ("ND5FDMUR", "032", 1),
    ("ND5FDH01", "034", 4),
    ("ND5FDH02", "038", 4),
    ("ND5FDH03", "03C", 2),
    ("ND5FDH04", "03E", 2),
    ("ND5FDH05", "040", 2),
    ("ND5FDH06", "042", 2),
    ("ND5FDH07", "044", 2),
    ("ND5FDH08", "046", 2),
    ("ND5FDH09", "048", 4),
    ("ND5FDH10", "04C", 2),
    ("ND5FDH11", "04E", 2),
    ("ND5FDH12", "050", 4),
    ("ND5FDTER", "05B", 3),
    ("ND5FDTCI", "05E", 2),
    ("ND5FDBTI", "060", 958),
    ("ND5FDLST", "FFE", 1),
]

# Convert hex string to ASCII
def hex_to_ascii(hex_str):
    try:
        bytes_object = bytes.fromhex(hex_str)
        return bytes_object.decode('cp037', errors='replace')  # EBCDIC to ASCII
    except:
        return ""

# Parse the input hex data
def parse_bti_record(input_lines):
    hex_data = ""
    for line in input_lines.splitlines():
        if "**" in line:
            hex_part = line.split("**")[0].strip()
            hex_data += hex_part.replace(" ", "")
    parsed_rows = []
    for field_name, offset, length in FIELD_DEFINITIONS:
        start = int(offset, 16) * 2
        end = start + (length * 2)
        hex_value = hex_data[start:end]
        parsed_rows.append({
            "Field Name": field_name,
            "Offset": offset,
            "Length": length,
            "Hex Value": hex_value
        })
    return pd.DataFrame(parsed_rows)

# Streamlit UI
st.title("BTI D5FD Record Parser")

input_data = st.text_area("Paste BTI D5FD Record Data Here", height=300)

if st.button("Parse Record"):
    if input_data.strip():
        df = parse_bti_record(input_data)
        st.subheader("Parsed Fields")
        st.dataframe(df)

        csv = df.to_csv(index=False).encode("utf-8")
        json = df.to_json(orient="records", indent=2)

        st.download_button("Download CSV", csv, "parsed_bti_record.csv", "text/csv")
        st.download_button("Download JSON", json, "parsed_bti_record.json", "application/json")
    else:
        st.warning("Please paste the BTI record data to parse.")
