# Reefed lab - imagem do app, do atacante e do validador.
FROM python:3.12-slim
WORKDIR /reefed
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common.py app.py attack.py validate.py ./
# Sem comando padrão: o compose do lab escolhe (app, attack ou validate).
ENTRYPOINT ["python"]
