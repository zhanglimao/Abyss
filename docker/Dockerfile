FROM python:3.12

WORKDIR /work

COPY . /work/

RUN pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt update && apt install -y nodejs && cd /work/Abyss_web && npm install && chmod +x /work/start.sh && mkdir -p /work/key_information

USER root

CMD ["/bin/bash", "-c", "/work/start.sh"]
