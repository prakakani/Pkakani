
import streamlit as st
import pandas as pd

# Define a simplified EBCDIC to ASCII map for demonstration
EBCDIC_TO_ASCII = {
    'C2': 'B', 'C1': 'A', 'C3': 'C', 'C4': 'D', 'C5': 'E', 'C6': 'F',
    'C7': 'G', 'C8': 'H', 'C9': 'I', 'D1': 'J', 'D2': 'K', 'D3': 'L',
    'D4': 'M', 'D5': 'N', 'D6': 'O', 'D7': 'P', 'D8': 'Q', 'D9': 'R',
    'E2': 'S', 'E3': 'T', 'E4': 'U', 'E5': 'V', 'E6': 'W', 'E7': 'X',
    'E8': 'Y', 'E9': 'Z', 'F0': '0', 'F1': '1', 'F2': '2', 'F3': '3',
    'F4': '4', 'F5': '5', 'F6': '6', 'F7': '7', 'F8': '8', 'F9': '9',
    '40': ' ', '4B': '.', '6B': ',', '5A': '$', '7A': '#', '6C': '<',
    '6E': '>', '50': '&', '60': '-', '7C': '|', '4E': '(', '5D': ')',
    '7D': '!', '6D': '=', '7E': '%', '4C': '*', '5C': ';', '6F': '?',
    '5E': ':', '4D': '+', 'BA': '@'
}

def decode_ebcdic(hex_str):
    return ''.join(EBCDIC_TO_ASCII.get(hex_str[i:i+2].upper(), '.') for i in range(0, len(hex_str), 2))

def parse_bti_record(input_text):
    lines = input_text.strip().splitlines()
    parsed_data = []

    for line in lines:
        if '**' in line:
            parts = line.split('**')
            hex_part = parts[0].strip().replace(' ', '')
            comment = parts[1].strip()
            ascii_part = decode_ebcdic(hex_part)
            parsed_data.append({
                'Hex': hex_part,
                'ASCII': ascii_part,
                'Comment': comment
            })

    return pd.DataFrame(parsed_data)

# Streamlit UI
st.title("BTI D5FD Record Parser")

input_data = st.text_area("Paste the raw BTI D5FD record data below:", height=300)

if st.button("Parse Record"):
    if input_data:
        df = parse_bti_record(input_data)
        st.dataframe(df)

        csv = df.to_csv(index=False).encode('utf-8')
        json = df.to_json(orient='records', indent=2).encode('utf-8')

        st.download_button("Download as CSV", csv, "parsed_bti_record.csv", "text/csv")
        st.download_button("Download as JSON", json, "parsed_bti_record.json", "application/json")
    else:
        st.warning("Please paste some BTI record data to parse.")
