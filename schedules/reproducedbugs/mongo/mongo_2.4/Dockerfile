FROM ubuntu:16.04
RUN apt-get update && apt-get install -y nano git python curl libpcap-dev pkg-config g++-4.8
RUN update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.8 50
#RUN ln -s /usr/bin/python2.5 /usr/bin/python
RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
RUN python get-pip.py
RUN pip install -U scons==2.5.1
RUN pip install -U setuptools
RUN pip install -U wheel
RUN mkdir /usr/local/lib/python2.7/dist-packages/lib/
RUN mkdir /usr/local/lib/python2.7/dist-packages/lib/scons
RUN mv /usr/local/lib/python2.7/dist-packages/scons-2.5.1/* /usr/local/lib/python2.7/dist-packages/lib/scons/
RUN git clone --branch r2.2.7 https://github.com/mongodb/mongo.git
WORKDIR /mongo
#RUN scons .
