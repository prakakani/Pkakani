import streamlit as st
from d5fd_file_parser import D5FDFileParser
import io

def main():
    st.title("D5FD Hex File Parser")
    st.write("Upload a hex dump file to parse and view the structured output.")

    uploaded_file = st.file_uploader("Choose a hex file", type=["txt"])
    if uploaded_file is not None:
        hex_data = uploaded_file.read().decode("utf-8")
        parser = D5FDFileParser()

        output_buffer = io.StringIO()
        parser.parse_record_to_file(hex_data, output_buffer)
        output_text = output_buffer.getvalue()

        st.subheader("Parsed Output")
        st.text_area("Output", output_text, height=500)

        st.download_button("Download Output", output_text, file_name="parsed_output.txt", mime="text/plain")

if __name__ == "__main__":
    main()
