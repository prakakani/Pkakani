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
        .section {
            background-color: #eaf2f8;
            padding: 5px;
            border-radius: 4px;
            margin-bottom: 5px;
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

def add_delta_logo():
    col1, col2 = st.columns([1, 5])
    with col1:
        st.markdown("""
        <div style="text-align: center;">
            <div style="width: 0; height: 0; border-left: 25px solid transparent; 
                       border-right: 25px solid transparent; border-bottom: 40px solid #003366; 
                       margin: 10px auto;"></div>
            <p style="margin: 5px 0 0 0; color: #003366; font-size: 12px; font-weight: bold;">DELTA</p>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("<h1 style='color: #333; font-size: 28px; margin-top: 15px; font-weight: bold;'>Core Ticketing - BTI Data Parser</h1>", unsafe_allow_html=True)

def main():
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
            parse_clicked = True
    else:
        hex_data = st.text_area("Paste hex data here", height=250)
        parse_clicked = st.button("Parse Data")

    st.markdown("</div>", unsafe_allow_html=True)

    if hex_data and parse_clicked:
        parser = D5FDFileParser()
        output_buffer = io.StringIO()
        parser.parse_record_to_file(hex_data, output_buffer)
        output_text = output_buffer.getvalue()

        st.markdown("<div class='section'>", unsafe_allow_html=True)
        st.subheader("Parsed Output")
        st.code(output_text, language=None)
        st.download_button("Download Output", output_text, file_name="parsed_output.txt", mime="text/plain")
        st.markdown("</div>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
