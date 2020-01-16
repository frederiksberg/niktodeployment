FROM python:3

RUN mkdir -p /opt/run

COPY ./python/* /opt/run/

RUN pip install -r /opt/run/requirements.txt

CMD ["python", "-u", "/opt/run/lookforupdates.py"]
