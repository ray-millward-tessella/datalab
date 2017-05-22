FROM node:7.10.0

LABEL maintainer "joshua.foster@stfc.ac.uk"

RUN mkdir -p /usr/src/api

WORKDIR /usr/src/api

COPY ./dist/api /usr/src/api

COPY ./package.json /usr/src/api

RUN yarn install --production

EXPOSE 8000

CMD ["node", "server.js"]