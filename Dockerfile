FROM fedora:28

RUN dnf install -y libgo

COPY threat-graph /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/threat-graph"]
CMD [ "/queue/input" ]

