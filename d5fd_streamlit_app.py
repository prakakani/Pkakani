import streamlit as st
from d5fd_file_parser import D5FDFileParser
import io

def main():
    st.title("Core Ticketing-BTI Data Parser")
    st.write("Choose an input method to provide BTI hex data for parsing.")

    input_method = st.radio("Choose input method:", ["Upload hex file", "Paste hex data"])

    hex_data = ""
    if input_method == "Upload hex file":
        uploaded_file = st.file_uploader("Upload a hex file", type=["txt"])
        if uploaded_file is not None:
            hex_data = uploaded_file.read().decode("utf-8")
    else:
        hex_data = st.text_area("Paste hex data here", height=300)

    if hex_data:
        parser = D5FDFileParser()
        output_buffer = io.StringIO()
        parser.parse_record_to_file(hex_data, output_buffer)
        output_text = output_buffer.getvalue()

        st.subheader("Parsed Output")
        st.text_area("Output", output_text, height=500)
        st.download_button("Download Output", output_text, file_name="parsed_output.txt", mime="text/plain")

if __name__ == "__main__":
    main()
