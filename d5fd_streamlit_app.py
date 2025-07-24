import streamlit as st
from d5fd_file_parser import D5FDFileParser
import io

st.title("D5FD Hex File Parser")

uploaded_file = st.file_uploader("Upload a hex data file", type=["txt"])

if uploaded_file is not None:
    hex_data = uploaded_file.read().decode("utf-8")
    parser = D5FDFileParser()
    output_buffer = io.StringIO()
    parser.parse_record_to_file(hex_data, output_buffer)
    output_text = output_buffer.getvalue()

    st.subheader("Parsed Output")
    st.text_area("Results", output_text, height=400)

    st.download_button(
        label="Download Parsed Output",
        data=output_text,
        file_name="parsed_output.txt",
        mime="text/plain"
    )
