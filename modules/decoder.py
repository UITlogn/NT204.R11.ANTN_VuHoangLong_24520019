import base64
import html
import quopri
import urllib.parse

def decode_payload(event):
    app = event.get("application")
    app_proto = event.get("application_protocol")

    if not app:
        return event

    decode_meta = {
        "decoded": False,
        "status": "clean",
        "details": []
    }

    if app_proto == "HTTP":
        if "uri" in app:
            raw_uri = app["uri"]
            try:
                dec_uri = urllib.parse.unquote(raw_uri)
                if dec_uri != raw_uri:
                    app["raw_uri"] = raw_uri
                    app["uri"] = dec_uri
                    decode_meta["decoded"] = True
                    decode_meta["details"].append("url_decode")
            except Exception as e:
                decode_meta["status"] = "partial"
                decode_meta["details"].append(f"url_error: {str(e)}")

        if "body" in app and isinstance(app["body"], str):
            orig_body = app["body"]
            try:
                dec_body = html.unescape(orig_body)
                if "%" in dec_body or "+" in dec_body:
                    dec_body = urllib.parse.unquote_plus(dec_body)

                if dec_body != orig_body:
                    app["raw_body"] = orig_body
                    app["body"] = dec_body
                    decode_meta["decoded"] = True
                    decode_meta["details"].append("html_form_decode")
            except Exception as e:
                decode_meta["status"] = "partial"
                decode_meta["details"].append(f"html_error: {str(e)}")

    elif app_proto == "SMTP":
        content = app.get("arguments") or app.get("body")
        encoding = app.get("encoding", "").lower()
        
        if content and encoding:
            try:
                if "base64" in encoding:
                    decoded_bytes = base64.b64decode(content)
                    app["decoded_content"] = decoded_bytes.decode("utf-8", errors="replace")
                    decode_meta["decoded"] = True
                    decode_meta["details"].append("mime_base64")
                elif "quoted-printable" in encoding:
                    decoded_bytes = quopri.decodestring(content.encode("ascii", errors="ignore"))
                    app["decoded_content"] = decoded_bytes.decode("utf-8", errors="replace")
                    decode_meta["decoded"] = True
                    decode_meta["details"].append("mime_qp")
            except Exception as e:
                decode_meta["status"] = "partial"
                decode_meta["details"].append(f"mime_error: {str(e)}")

    event["decode_status"] = decode_meta
    return event