FROM node:22-alpine

WORKDIR /workspace

ENTRYPOINT ["npm"]
CMD ["--help"]
