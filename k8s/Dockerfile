FROM busybox

COPY script.sh script.sh
RUN chmod +x script.sh

ENTRYPOINT ["sh", "-c", "./script.sh"]