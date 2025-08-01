import streamlit as st
from d5fd_file_parser import D5FDFileParser
import io
import re

# Set wide layout and page title
st.set_page_config(page_title="Core Ticketing - BTI Data Parser", layout="wide")

# Inject custom CSS for styling and smaller fonts
st.markdown("""
    <style>
        /* Completely hide all possible header elements */
        header[data-testid="stHeader"] {
            display: none !important;
            visibility: hidden !important;
            height: 0px !important;
            position: absolute !important;
            top: -9999px !important;
        }
        .stApp > header {
            display: none !important;
        }
        .stDeployButton {
            display: none !important;
        }
        div[data-testid="stToolbar"] {
            display: none !important;
        }
        div[data-testid="stDecoration"] {
            display: none !important;
        }
        div[data-testid="stStatusWidget"] {
            display: none !important;
        }
        #MainMenu {
            display: none !important;
        }
        footer {
            display: none !important;
        }
        .viewerBadge_container__1QSob {
            display: none !important;
        }
        .stAppViewContainer > .main {
            padding-top: 0rem !important;
        }
        .block-container {
            padding-top: 0rem !important;
        }
        .element-container:first-child {
            margin-top: 0rem !important;
        }
        .stApp {
            margin-top: 0px !important;
        }
        body {
            background-color: #f4f8fc;
            margin-top: 0px !important;
        }
        .main-container h1 {
            color: white !important;
            font-size: 18px !important;
            text-align: center !important;
            margin: 0px !important;
            padding: 10px 0px !important;
            background-color: #1e3a8a !important;
            border-radius: 2px !important;
        }
        h1 {
            color: white !important;
            font-size: 15px !important;
            text-align: center !important;
            margin: 0px !important;
            padding: 10px 0px !important;
            background-color: #1e3a8a !important;
            border-radius: 2px !important;
        }
        h1 {
            color: white !important;
            font-size: 22px !important;
            text-align: center !important;
            margin: 0px !important;
            padding: 10px 0px !important;
            background-color: #007bff !important;
            border-radius: 2px !important;
        }
        .section {
            background-color: #eaf2f8;
            padding: 5px;
            border-radius: 4px;
            margin-bottom: 5px;
        }
        .output-box {
            background-color: #fdfefe;
            padding: 5px;
            border-radius: 5px;
            border: 1px solid #ccc;
            font-family: monospace;
            white-space: pre-wrap;
            overflow-x: auto;
            width: 100%;
            font-size: 12px;
        }
        .stTextArea textarea {
            font-size: 14px !important;
        }
        .stButton > button {
            background-color: #007bff !important;
            color: white !important;
            border: none !important;
        }
        .stButton > button:hover {
            background-color: #0056b3 !important;
        }
        .stRadio > div {
            flex-direction: row;
        }
        .stRadio > div > label > div:first-child {
            background-color: #007bff !important;
        }
        .stRadio > div > label > div:first-child > div {
            background-color: white !important;
        }
        .stDownloadButton > button {
            background-color: #007bff !important;
            color: white !important;
            border: none !important;
        }
        .stDownloadButton > button:hover {
            background-color: #0056b3 !important;
        }
    </style>
""", unsafe_allow_html=True)

def format_output_with_dynamic_widths(output_text):
    """Format output with dynamic column widths based on actual data"""
    lines = output_text.split('\n')
    data_lines = []
    
    # Parse data lines to find maximum widths
    max_field_width = len("Field")
    max_offset_width = len("Offset")
    max_length_width = len("Len")
    max_hex_width = len("Hex")
    max_value_width = len("Value")
    
    for line in lines:
        # Look for data lines with the pattern: FieldName OffsetH Length HexValue Value Description
        parts = line.split()
        if len(parts) >= 5 and len(parts[0]) > 0 and parts[1].endswith('h') and parts[2].isdigit():
            field_name = parts[0]
            offset = parts[1]
            length = parts[2]
            hex_value = parts[3]
            
            # Find value and description
            remaining = ' '.join(parts[4:])
            # Split at first space after non-space characters for value
            value_match = re.match(r'^(\S+)\s*(.*)', remaining)
            if value_match:
                value = value_match.group(1)
                description = value_match.group(2)
            else:
                value = remaining
                description = ""
            
            # Update max widths
            max_field_width = max(max_field_width, len(field_name))
            max_offset_width = max(max_offset_width, len(offset))
            max_length_width = max(max_length_width, len(length))
            max_hex_width = max(max_hex_width, len(hex_value))
            max_value_width = max(max_value_width, len(value))
            
            data_lines.append((field_name, offset, length, hex_value, value, description))
    
    # Add padding to widths
    max_field_width += 2
    max_offset_width += 2
    max_length_width += 2
    max_hex_width += 2
    max_value_width += 2
    
    # Rebuild output with proper formatting
    processed_lines = []
    
    for line in lines:
        # Handle header lines
        if ('Field Name' in line or 'Field' in line) and 'Offset' in line and ('Length' in line or 'Len' in line):
            header = (f"{'Field':<{max_field_width}}"
                     f"{'Offset':<{max_offset_width}}"
                     f"{'Len':<{max_length_width}}"
                     f"{'Hex':<{max_hex_width}}"
                     f"{'Value':<{max_value_width}}"
                     f"Description")
            processed_lines.append(header)
        elif line.startswith('-'):
            # Create dynamic separator
            total_width = max_field_width + max_offset_width + max_length_width + max_hex_width + max_value_width + 15
            processed_lines.append('-' * min(total_width, 120))
        elif line.startswith('='):
            processed_lines.append('=' * 80)
        else:
            # Check if this is a data line we parsed
            found_data = False
            for data in data_lines:
                if line.startswith(data[0]) and data[1] in line:
                    formatted_line = (f"{data[0]:<{max_field_width}}"
                                    f"{data[1]:<{max_offset_width}}"
                                    f"{data[2]:<{max_length_width}}"
                                    f"{data[3]:<{max_hex_width}}"
                                    f"{data[4]:<{max_value_width}}"
                                    f"{data[5]}")
                    processed_lines.append(formatted_line)
                    found_data = True
                    break
            
            if not found_data:
                processed_lines.append(line)
    
    return '\n'.join(processed_lines)

def add_delta_logo():
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.image("delta_logo.png", width=200)
        st.markdown("<p style='text-align: center; color: #333; font-size: 18px; margin-top: 10px; font-weight: bold;'>Core Ticketing - BTI Data Parser</p>", unsafe_allow_html=True)

def main():
    st.markdown("<div class='main-container'>", unsafe_allow_html=True)
    add_delta_logo()
    st.markdown("<hr style='margin: 20px 0;'>", unsafe_allow_html=True)
    st.markdown("<div class='section'>", unsafe_allow_html=True)
    st.write("Choose an input method to provide BTI hex data for parsing.")

    input_method = st.radio("Choose input method:", ["Upload hex file", "Paste hex data"])

    hex_data = ""
    parse_clicked = False
    
    if input_method == "Upload hex file":
        uploaded_file = st.file_uploader("Upload a hex file", type=["txt"])
        if uploaded_file is not None:
            hex_data = uploaded_file.read().decode("utf-8")
            parse_clicked = True  # Auto-parse for uploaded files
    else:
        hex_data = st.text_area("Paste hex data here", height=250)
        parse_clicked = st.button("Parse Data")

    st.markdown("</div>", unsafe_allow_html=True)

    if hex_data and parse_clicked:
        parser = D5FDFileParser()
        output_buffer = io.StringIO()
        parser.parse_record_to_file(hex_data, output_buffer)
        output_text = output_buffer.getvalue()

        # Format with dynamic column widths
        formatted_output = format_output_with_dynamic_widths(output_text)

        st.markdown("<div class='section'>", unsafe_allow_html=True)
        st.subheader("Parsed Output")
        st.code(formatted_output, language=None)
        st.download_button("Download Output", output_text, file_name="parsed_output.txt", mime="text/plain")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
