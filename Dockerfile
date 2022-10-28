FROM node:alpine

USER node
COPY ./ /home/node

CMD node /home/node
