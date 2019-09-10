FROM node:12.4.0-stretch

# Create the home directory for the new app user.
RUN mkdir -p /home/app

## CREATE APP USER ##
# Create an app user so our application doesn't run as root.
RUN groupadd -r app &&\
    useradd -r -g app -d /home/app -s /sbin/nologin -c "Docker image user" app

# Create app directory
ENV HOME=/home/app
ENV APP_HOME=/home/app/access-control-srv

## SETTING UP THE APP ##
RUN mkdir $APP_HOME
WORKDIR $APP_HOME
RUN apt-get update && apt-get install -y libc6-dev

# Install app dependencies
RUN npm install -g typescript
# Set config volumes
VOLUME $APP_HOME/cfg
VOLUME $APP_HOME/protos

# Bundle app source
ADD . $APP_HOME

# Chown all the files to the app user.
RUN chown -R app:app $HOME
RUN cd $APP_HOME
RUN pwd

# Change to the app user.
USER app
RUN npm install

EXPOSE 50051
CMD [ "npm", "start" ]

# To build the image:
# docker build -t restorecommerce/access-control-srv .
#
# To create a container:
# docker create --name access-control-srv --net restorecms_default restorecommerce/access-control-srv
#
# To run the container:
# docker start access-control-srv
