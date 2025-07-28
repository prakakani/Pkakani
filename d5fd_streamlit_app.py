import streamlit as st
from d5fd_file_parser import D5FDFileParser
import io

# Set wide layout and page title
st.set_page_config(page_title="Core Ticketing - BTI Data Parser", layout="wide")

# Inject custom CSS for styling and smaller fonts
st.markdown("""
    <style>
        body {
            background-color: #f4f8fc;
        }
        .main-container {
            background-color: #ffffff;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            max-width: 100%;
            margin: auto;
            font-size: 14px;
        }
        h1 {
            color: #2c3e50;
            font-size: 1.8em;
            text-align: center;
        }
        .section {
            background-color: #eaf2f8;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .output-box {
            background-color: #fdfefe;
            padding: 10px;
            border-radius: 8px;
            border: 1px solid #ccc;
            font-family: monospace;
            white-space: pre-wrap;
            overflow-x: auto;
            width: 100%;
            font-size: 12px;
        }
        .stTextArea textarea {
            font-size: 12px !important;
        }
    </style>
""", unsafe_allow_html=True)

def main():
    st.markdown("<div class='main-container'>", unsafe_allow_html=True)
    st.markdown("<h1>Core Ticketing – BTI Data Parser</h1>", unsafe_allow_html=True)
    st.markdown("<div class='section'>", unsafe_allow_html=True)
    st.write("Choose an input method to provide BTI hex data for parsing.")

    input_method = st.radio("Choose input method:", ["Upload hex file", "Paste hex data"])

    hex_data = ""
    if input_method == "Upload hex file":
        uploaded_file = st.file_uploader("Upload a hex file", type=["txt"])
        if uploaded_file is not None:
            hex_data = uploaded_file.read().decode("utf-8")
    else:
        hex_data = st.text_area("Paste hex data here", height=250)

    st.markdown("</div>", unsafe_allow_html=True)

    if hex_data:
        parser = D5FDFileParser()
        output_buffer = io.StringIO()
        parser.parse_record_to_file(hex_data, output_buffer)
        output_text = output_buffer.getvalue()

        # Shorten dashed lines and column headers
        output_text = output_text.replace("=" * 60, "=" * 40)
        output_text = output_text.replace("-" * 60, "-" * 40)
        output_text = output_text.replace("Field Name", "Field")
        output_text = output_text.replace("Offset", "Off")
        output_text = output_text.replace("Length", "Len")
        output_text = output_text.replace("HEX Value", "Hex")
        output_text = output_text.replace("Description", "Desc")

        st.markdown("<div class='section'>", unsafe_allow_html=True)
        st.subheader("Parsed Output")
        st.markdown(f"<div class='output-box'>{output_text}</div>", unsafe_allow_html=True)
        st.download_button("Download Output", output_text, file_name="parsed_output.txt", mime="text/plain")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
