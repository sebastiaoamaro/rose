#!/bin/bash
if [ -z "$1" ]; then
  echo "Usage: $0 <java-version>"
  exit 1
fi

JAVA_VERSION=$1
JAVA_PATH="/usr/lib/jvm/java-${JAVA_VERSION}-openjdk-amd64"

# Check if the directory exists
if [ ! -d "$JAVA_PATH" ]; then
  echo "Error: Java version $JAVA_VERSION not found in $JAVA_PATH"
  echo "Install it with: sudo apt install openjdk-${JAVA_VERSION}-jdk"
  exit 1
fi

echo ">> Switching Java to version $JAVA_VERSION..."

sudo update-alternatives --install /usr/bin/java java $JAVA_PATH/bin/java $JAVA_VERSION
sudo update-alternatives --install /usr/bin/javac javac $JAVA_PATH/bin/javac $JAVA_VERSION

sudo update-alternatives --set java $JAVA_PATH/bin/java
sudo update-alternatives --set javac $JAVA_PATH/bin/javac

echo ">> Current Java version is now:"
java -version
