import azure.functions as func
import datetime
import json
import logging
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timezone


app = func.FunctionApp()

def validate_certificate(req: func.HttpRequest) -> bool:
    logging.info('Validating certificate...')

    try:
        cert_value =  req.headers.get('X-ARR-ClientCert') 
        if not cert_value:
            logging.error('No certificate found in request headers.')
            raise Exception("No certificate found in request headers.")

        cert_data = ''.join(['-----BEGIN CERTIFICATE-----\n', cert_value, '\n-----END CERTIFICATE-----\n',])
        cert = x509.load_pem_x509_certificate(cert_data.encode('utf-8'))
    
        subject = cert.subject
        subject_cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if subject_cn != os.environ["SUBJECT_CN"]:
            logging.error(f'Subject common name mismatch: {subject_cn}')
            raise Exception(f'Subject common name mismatch: {subject_cn}')
        
        issuer = cert.issuer
        issuer_cn = issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if issuer_cn != os.environ["ISSUER_CN"]:
            logging.error(f'Issuer common name mismatch: {issuer_cn}')
            raise Exception(f'Issuer common name mismatch: {issuer_cn}')
    
        current_time = datetime.now(timezone.utc)
    
        if current_time < cert.not_valid_before_utc:
            raise Exception(f"Certificate not valid before {cert.not_valid_before_utc}")
        
        if current_time > cert.not_valid_after_utc:
            raise Exception(f"Certificate expired at {cert.not_valid_after_utc}")
       
    except Exception as e:
        # Handle any errors encountered during validation.
        print(f"Encountered the following error during certificate validation: {e}")
        raise Exception(f"Encountered the following error during certificate validation: {e}")


@app.route(route="http_trigger", auth_level=func.AuthLevel.ANONYMOUS)
def http_trigger(req: func.HttpRequest) -> func.HttpResponse:
    validate_certificate(req)
    logging.info('Python HTTP trigger function processed a request.')

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    if name:
        return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
             status_code=200
        )

@app.route(route="healthz", auth_level=func.AuthLevel.ANONYMOUS)
def health_trigger(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Health check triggered.')
    return func.HttpResponse(f"Healthy and headers are: {json.dumps(dict(req.headers))}")