FROM registry.access.redhat.com/ubi9/python-39:latest

# By default, listen on port 5000
EXPOSE 5000/tcp

# Set the working directory in the container
WORKDIR /projects

# Copy the dependencies file to the working directory
COPY requirements.txt .

# Install any dependencies
RUN python -m pip install --upgrade pip
RUN pip install wheel packaging
RUN pip install -r requirements.txt

# Copy the content of the local src directory to the working directory
COPY . .

# Specify the command to run on container start
CMD [ "flask", "--app", "liana", "--debug", "run", "--host=0.0.0.0" ]
