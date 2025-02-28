#!/bin/bash

# Exit on any error
set -e

# Get current user and group
CURRENT_USER=$(whoami)
CURRENT_GROUP=$(id -gn)

# Version information - update these values for new releases
GOGOGADGET_VERSION="1.1"
GOGOGADGET_CODENAME="umbrella"

# Function to check if command was successful
check_status() {
    if [ $? -eq 0 ]; then
        echo "Go Go Gadget Success! ✓ $1"
    else
        echo "Dr. Claw's Interference! ✗ Error: $1"
        exit 1
    fi
}

# Function to check Go installation
check_go_installation() {
    if ! command -v go &> /dev/null; then
        echo "Penny: \"Uncle Gadget, Go is not installed!\""
        return 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    if [[ "${GO_VERSION}" < "1.18" ]]; then
        echo "Brain: \"Woof! Go version ${GO_VERSION} is too old. We need 1.18 or higher!\""
        return 1
    fi
    
    return 0
}

# Function to check required modules
check_required_modules() {
    if ! go list github.com/go-ping/ping &> /dev/null || ! go list github.com/gosnmp/gosnmp &> /dev/null; then
        echo "Penny: \"Uncle Gadget, some required modules are missing!\""
        return 1
    fi
    return 0
}

# Pre-installation checks
echo "Penny: \"Let me check the requirements first, Uncle Gadget!\""
GO_NEEDS_INSTALL=false
MODULES_NEED_INSTALL=false

if ! check_go_installation; then
    GO_NEEDS_INSTALL=true
fi

if ! check_required_modules; then
    MODULES_NEED_INSTALL=true
fi

# ASCII art and opening
cat << "EOF"
                                                         
   _____       _____       _____           _            _   
  / ____|     / ____|     / ____|         | |          | |  
 | |  __  ___| |  __  ___| |  __  __ _  __| | __ _  ___| |_ 
 | | |_ |/ _ \ | |_ |/ _ \ | |_ |/ _` |/ _` |/ _` |/ _ \ __|
 | |__| | (_) | |__| | (_) | |__| (_| | (_| | (_| |  __/ |_ 
  \_____|\___/ \_____|\___/ \_____\__,_|\__,_|\__, |\___|\__|
                                               __/ |          
                                              |___/           
EOF

echo -e "\nInspector Gadget: \"Wowzers! Welcome to the GoGoGadget Installation!\""
echo "Chief Quimby: \"This installation is TOP SECRET, Inspector!\""
echo -e "Penny: \"Uncle Gadget, we need to choose an installation type!\"\n"

# Interactive menu
echo "Brain shows a helpful sign:"
echo "----------------------------------------"
echo "Please select installation type:"
echo "1) Server"
echo "2) Proxy"
echo "3) Uninstall"
echo "4) Cancel"
echo "----------------------------------------"
echo -n "Enter your choice: "
read choice

case $choice in
    1)
        INSTALL_TYPE="server"
        ;;
    2)
        INSTALL_TYPE="proxy"
        ;;
    3)
        echo -e "\nPenny: \"Uncle Gadget, this will remove all GoGoGadget components!\""
        read -p "Are you sure you want to uninstall? (y/n): " confirm
        if [[ $confirm != [yY] && $confirm != [yY][eE][sS] ]]; then
            echo "Inspector Gadget: \"Go Go Gadget Abort!\""
            exit 0
        fi
        
        echo "Inspector Gadget: \"Go Go Gadget Uninstaller!\""
        
        # Stop and disable services
        echo "Penny: \"Stopping services...\""
        sudo systemctl stop gogogadget-server 2>/dev/null || true
        sudo systemctl stop gogogadget-proxy 2>/dev/null || true
        sudo systemctl disable gogogadget-server 2>/dev/null || true
        sudo systemctl disable gogogadget-proxy 2>/dev/null || true
        
        # Remove service files
        echo "Brain: \"Removing service files...\""
        sudo rm -f /etc/systemd/system/gogogadget-server.service
        sudo rm -f /etc/systemd/system/gogogadget-proxy.service
        sudo systemctl daemon-reload
        
        # Remove binary
        echo "Chief Quimby: \"Removing binary...\""
        sudo rm -f /usr/local/bin/gogogadget
        
        # Remove directories and logs
        echo "Inspector Gadget: \"Removing directories and logs...\""
        sudo rm -rf /opt/gogogadget
        sudo rm -rf /var/log/gogogadget
        
        echo -e "\nPenny: \"Uninstallation complete, Uncle Gadget!\""
        echo "Dr. Claw: \"You haven't seen the last of me, GADGET!\""
        exit 0
        ;;
    4)
        echo -e "\nPenny: \"Installation cancelled, Uncle Gadget!\""
        echo "Dr. Claw: \"You'll be back, GADGET!\""
        exit 0
        ;;
    *)
        echo "Dr. Claw: \"NEXT TIME, GADGET! Choose 1, 2, 3, or 4!\""
        echo "M.A.D. Cat: \"MEOW!\""
        exit 1
        ;;
esac

echo -e "\nPenny: \"This installation requires:"
if [ "$GO_NEEDS_INSTALL" = true ]; then
    echo "  - Go 1.18 or higher (will be installed via apt)"
fi
if [ "$MODULES_NEED_INSTALL" = true ]; then
    echo "  - Required Go modules (will be installed during setup)"
fi
echo -e "\nThis installation will:"
echo "  - Set up GoGoGadget $INSTALL_TYPE"
echo "  - Create necessary directories and services"
echo -e "Are you sure you want to proceed? (y/n)\""
read -p "Enter choice (y/n): " confirm

if [[ $confirm != [yY] && $confirm != [yY][eE][sS] ]]; then
    echo "Inspector Gadget: \"Go Go Gadget Abort!\""
    echo "Dr. Claw: \"Running away, GADGET?\""
    exit 0
fi

echo "Inspector Gadget: \"Go Go Gadget $INSTALL_TYPE Installation!\""

# Check if Go is installed and version
if [ "$GO_NEEDS_INSTALL" = true ]; then
    echo -e "\nPenny: \"Uncle Gadget, we need Go 1.18 or higher for this installation!\""
    if ! command -v go &> /dev/null; then
        echo "Brain: \"Installing Go using apt...\""
        sudo apt update
        sudo apt install -y golang-go
        
        # Check if installation was successful
        if ! command -v go &> /dev/null; then
            echo "Dr. Claw: \"Go installation failed, GADGET!\""
            echo -e "\nBrain shows manual instructions:"
            echo "----------------------------------------"
            echo "1. Download Go from: https://go.dev/dl/"
            echo "2. Install Go 1.18 or higher"
            echo "3. Add Go to your PATH"
            echo "4. Run this installer again"
            echo "----------------------------------------"
            exit 1
        fi
    fi
    
    # Check version after installation
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    if [[ "${GO_VERSION}" < "1.18" ]]; then
        echo "Brain: \"Woof! Current version ${GO_VERSION} is too old!\""
        echo -e "\nBrain shows instructions:"
        echo "----------------------------------------"
        echo "1. Download Go 1.18 or higher from: https://go.dev/dl/"
        echo "2. Update your Go installation"
        echo "3. Run this installer again"
        echo "----------------------------------------"
        echo -e "\nInspector Gadget: \"Go Go Gadget Abort!\""
        echo "Dr. Claw: \"Install newer Go version first, GADGET!\""
        exit 1
    fi
else
    echo "Penny: \"Go is already at the right version, Uncle Gadget!\""
fi

# Create directories
echo "Inspector Gadget: \"Time to create our secret headquarters!\""
sudo mkdir -p /opt/gogogadget
sudo mkdir -p /var/log/gogogadget
sudo chown -R $CURRENT_USER:$CURRENT_GROUP /opt/gogogadget
sudo chown -R $CURRENT_USER:$CURRENT_GROUP /var/log/gogogadget
sudo chmod -R 755 /opt/gogogadget
sudo chmod -R 755 /var/log/gogogadget
check_status "Directory Creation"

# Create log file with proper permissions based on installation type
if [ "$INSTALL_TYPE" == "server" ]; then
    sudo touch /var/log/gogogadget/server.log
    sudo chown $CURRENT_USER:$CURRENT_GROUP /var/log/gogogadget/server.log
    sudo chmod 644 /var/log/gogogadget/server.log
    check_status "Server Log File Creation"
else
    sudo touch /var/log/gogogadget/proxy.log
    sudo chown $CURRENT_USER:$CURRENT_GROUP /var/log/gogogadget/proxy.log
    sudo chmod 644 /var/log/gogogadget/proxy.log
    check_status "Proxy Log File Creation"
fi

echo "Wowzers! Starting GoGoGadget installation..."

# Create temporary build directory
echo "Go Go Gadget Workspace!"
TEMP_DIR=$(mktemp -d)
cp gogogadget.go "$TEMP_DIR/"
cd "$TEMP_DIR"

# Initialize Go module
echo "Go Go Gadget Module Creator!"
go mod init gogogadget
check_status "Module Init"

# Add dependencies
echo "Go Go Gadget Dependencies!"
go get github.com/go-ping/ping@v1.1.0
go get github.com/gosnmp/gosnmp@v1.35.0
go mod tidy
check_status "Dependencies"

# Check if this is an update
if [ -f /usr/local/bin/gogogadget ]; then
    echo "Penny: \"Uncle Gadget, it looks like we're updating an existing installation!\""
    
    # Check if the specific service is running
    if systemctl is-active --quiet "gogogadget-${INSTALL_TYPE}"; then
        echo "Dr. Claw: \"Found running gogogadget-${INSTALL_TYPE} service!\""
        echo "Penny: \"Don't worry Uncle Gadget, I'll stop it for you.\""
        sudo systemctl stop "gogogadget-${INSTALL_TYPE}"
        sleep 2  # Give it time to fully stop
        
        if systemctl is-active --quiet "gogogadget-${INSTALL_TYPE}"; then
            echo "Dr. Claw: \"Failed to stop the service! Please stop it manually.\""
            echo -e "\nTo complete the update:"
            echo "1. Stop the service: sudo systemctl stop gogogadget-${INSTALL_TYPE}"
            echo "2. Run this installer again"
            exit 1
        fi
        echo "Penny: \"Service stopped successfully!\""
    fi
    
    # Copy new configs if they exist
    if [ -d configs ]; then
        echo "Brain: \"Updating configuration files...\""
        if [ "$INSTALL_TYPE" == "server" ]; then
            [ -f configs/constants.json ] && cp configs/constants.json /opt/gogogadget/
            [ -f configs/server_config.json ] && cp configs/server_config.json /opt/gogogadget/
            sudo chown $CURRENT_USER:$CURRENT_GROUP /opt/gogogadget/constants.json 2>/dev/null || true
            sudo chown $CURRENT_USER:$CURRENT_GROUP /opt/gogogadget/server_config.json 2>/dev/null || true
            sudo chmod 644 /opt/gogogadget/constants.json 2>/dev/null || true
            sudo chmod 644 /opt/gogogadget/server_config.json 2>/dev/null || true
            check_status "Server Configuration Update"
        else
            [ -f configs/constants.json ] && cp configs/constants.json /opt/gogogadget/
            sudo chown $CURRENT_USER:$CURRENT_GROUP /opt/gogogadget/constants.json 2>/dev/null || true
            sudo chmod 644 /opt/gogogadget/constants.json 2>/dev/null || true
            check_status "Proxy Configuration Update"
        fi
    fi
fi

# Build binary
echo "Go Go Gadget Builder!"
go build -o gogogadget
check_status "Binary Build"

# Install binary
echo "Go Go Gadget Installer!"
sudo cp gogogadget /usr/local/bin/
sudo chown $CURRENT_USER:$CURRENT_GROUP /usr/local/bin/gogogadget
sudo chmod 755 /usr/local/bin/gogogadget
check_status "Binary Install"

# Create version file if it doesn't exist
echo "Brain: \"Creating version information...\""
cat > version.txt << EOF
VERSION=${GOGOGADGET_VERSION}
CODENAME=${GOGOGADGET_CODENAME}
EOF

# Install version file
echo "Brain: \"Installing version information...\""
sudo cp version.txt /usr/local/bin/
if [ $? -ne 0 ]; then
    echo "Dr. Claw: \"Failed to install version information!\""
    exit 1
fi

# Make sure the version file is readable
sudo chmod 644 /usr/local/bin/version.txt
if [ $? -ne 0 ]; then
    echo "Dr. Claw: \"Failed to set version file permissions!\""
    exit 1
fi

echo "Go Go Gadget Success! ✓ Version Info"

# Cleanup
cd - > /dev/null
rm -rf "$TEMP_DIR"

# Copy configs
echo "Chief Quimby: \"Here's your TOP SECRET configuration files, Gadget!\""
if [ "$INSTALL_TYPE" == "server" ]; then
    cp configs/constants.json /opt/gogogadget/
    cp configs/server_config.json /opt/gogogadget/
    sudo chown $CURRENT_USER:$CURRENT_GROUP /opt/gogogadget/constants.json
    sudo chown $CURRENT_USER:$CURRENT_GROUP /opt/gogogadget/server_config.json
    sudo chmod 644 /opt/gogogadget/constants.json
    sudo chmod 644 /opt/gogogadget/server_config.json
    check_status "Server Configuration"
else
    cp configs/constants.json /opt/gogogadget/
    sudo chown $CURRENT_USER:$CURRENT_GROUP /opt/gogogadget/constants.json
    sudo chmod 644 /opt/gogogadget/constants.json
    check_status "Proxy Configuration"
fi

# Create service
echo "Go Go Gadget Service Creator!"
if [ "$INSTALL_TYPE" == "server" ]; then
    sudo bash -c "cat > /etc/systemd/system/gogogadget-server.service" << EOF
[Unit]
Description=Go Go Gadget Server
After=network.target

[Service]
Type=simple
User=$CURRENT_USER
Group=$CURRENT_GROUP
ExecStart=/usr/local/bin/gogogadget server
WorkingDirectory=/opt/gogogadget
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    SERVICE_NAME="gogogadget-server"
else
    sudo bash -c "cat > /etc/systemd/system/gogogadget-proxy.service" << EOF
[Unit]
Description=Go Go Gadget Proxy
After=network.target

[Service]
Type=simple
User=$CURRENT_USER
Group=$CURRENT_GROUP
ExecStart=/usr/local/bin/gogogadget proxy
WorkingDirectory=/opt/gogogadget
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    SERVICE_NAME="gogogadget-proxy"
fi
check_status "Service Creation"

# Start service
echo "Inspector Gadget: \"Time to activate our gadgets!\""
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME
sudo systemctl start $SERVICE_NAME
check_status "Service Activation"

echo -e "\nInspector Gadget: \"Installation complete!\""
echo "Penny: \"You can check the service status with:\""
echo "systemctl status $SERVICE_NAME"

# Test the installation
if [ "$INSTALL_TYPE" == "server" ]; then
    echo -e "\nGo Go Gadget Tester!"
    sleep 2
    
    # Get version info
    VERSION=$(cat /usr/local/bin/version.txt | grep VERSION | cut -d= -f2)
    CODENAME=$(cat /usr/local/bin/version.txt | grep CODENAME | cut -d= -f2)
    
    echo "Version: $VERSION ($CODENAME)"
    echo "----------------------------------------"
    echo "IP              HOSTNAME             STATUS"
    echo "----------------------------------------"
    
    # Check if jq is available, if not use grep and awk
    if command -v jq >/dev/null 2>&1; then
        curl -s http://localhost:8080/status | jq -r '.proxies[] | 
            [.address | split(":")[0], .hostname, if .available then "✓" else "✗" end] | 
            "%-15s %-20s %s" % .'
    else
        # Fallback to basic formatting with grep and awk
        curl -s http://localhost:8080/status | grep -o '"address":"[^"]*"\|"hostname":"[^"]*"\|"available":[^,}]*' | \
            awk -F'"' '
            BEGIN {count=0}
            {
                if ($2 == "address") {split($4,addr,":"); ip[int(count/3)]=addr[1]}
                if ($2 == "hostname") {host[int(count/3)]=$4}
                if ($0 ~ "available") {avail[int(count/3)]=$0; count++}
            }
            END {
                for(i=0;i<count/3;i++) {
                    status = (avail[i] ~ "true") ? "✓" : "✗"
                    printf("%-15s %-20s %s\n", ip[i], host[i], status)
                }
            }'
    fi
    
    echo -e "\nWowzers! Installation test complete!"
fi

# Remove cleanup section at the end that was deleting files
echo -e "\nPenny: \"Installation complete, Uncle Gadget!\""
echo -e "Dr. Claw: \"I'LL GET YOU NEXT TIME, GADGET! NEXT TIME!\""

# Create service file with version information
cat > /etc/systemd/system/gogogadget.service << EOF
[Unit]
Description=Go Go Gadget Service
After=network.target

[Service]
Type=simple
User=root
Environment=GOGOGADGET_VERSION=${GOGOGADGET_VERSION}
Environment=GOGOGADGET_CODENAME=${GOGOGADGET_CODENAME}
ExecStart=/usr/local/bin/gogogadget \$ROLE
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd to recognize the new service
systemctl daemon-reload

echo "Go Go Gadget installed successfully!"
echo "Version: ${GOGOGADGET_VERSION}"
echo "Codename: ${GOGOGADGET_CODENAME}" 