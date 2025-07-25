import streamlit as st
from d5fd_file_parser import D5FDFileParser
import io

# Set wide layout and page title
st.set_page_config(page_title="Delta Airlines - BTI D5FD Parser", layout="wide")

# Custom CSS for styling and Delta branding
st.markdown(
    """
    <style>
    .reportview-container .main .block-container {
        padding-top: 2rem;
        padding-right: 5rem;
        padding-left: 5rem;
        max-width: 95%;
    }
    .delta-header {
        display: flex;
        align-items: center;
        gap: 20px;
    }
    .delta-logo {
        height: 60px;
    }
    .delta-title {
        font-size: 2.5rem;
        font-weight: bold;
        color: #003366;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Sidebar with app info
st.sidebar.image("https://upload.wikimedia.org/wikipedia/commons/thumb/6/6e/Delta_Air_Lines_Logo.svg/2560px-Delta_Air_Lines_Logo.svg.png", use_column_width=True)
st.sidebar.title("Delta Airlines")
st.sidebar.markdown("**BTI D5FD Record Parser**")
st.sidebar.markdown("Upload a BTI hex dump file to parse and view structured output.")

# Main header with logo and title
st.markdown(
    """
    <div class="delta-header">
        https://upload.wikimedia.org/wikipedia/commons/thumb/6/6e/Delta_Air_Lines_Logo.svg/2560px-Delta_Air_Lines_Logo.svg.png
        <div class="delta-title">BTI D5FD Record Parser</div>
    </div>
    """,
    unsafe_allow_html=True
)

st.write("Upload a hex dump file to parse and view the structured output.")

uploaded_file = st.file_uploader("Choose a hex file", type=["txt"])
if uploaded_file is not None:
    hex_data = uploaded_file.read().decode("utf-8")
    parser = D5FDFileParser()

    output_buffer = io.StringIO()
    parser.parse_record_to_file(hex_data, output_buffer)
    output_text = output_buffer.getvalue()

    st.subheader("Parsed Output")
    st.text_area("Output", output_text, height=700)
    st.download_button("Download Output", output_text, file_name="parsed_output.txt", mime="text/plain")
