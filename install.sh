#!/bin/bash

# Linux Server Auditor Installation Script
# This script installs the Linux Server Auditor tool and its dependencies

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/linux-server-auditor"
SERVICE_USER="auditor"
PYTHON_VERSION="3.8"

# Logging
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect Linux distribution
detect_distribution() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif command -v lsb_release &> /dev/null; then
        DISTRO=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        VERSION=$(lsb_release -sr)
    else
        error "Cannot detect Linux distribution"
        exit 1
    fi
    
    log "Detected distribution: $DISTRO $VERSION"
}

# Install system dependencies
install_system_dependencies() {
    log "Installing system dependencies..."
    
    case $DISTRO in
        ubuntu|debian)
            apt-get update
            apt-get install -y \
                python3.8 \
                python3.8-pip \
                python3.8-venv \
                sudo \
                lastlog \
                iproute2 \
                curl \
                wget \
                git
            ;;
        centos|rhel|rocky|almalinux)
            # Enable EPEL repository if needed
            if ! rpm -q epel-release &> /dev/null; then
                yum install -y epel-release || dnf install -y epel-release
            fi
            
            # Install Python 3.8+ (use latest available)
            yum install -y \
                python3 \
                python3-pip \
                sudo \
                util-linux \
                iproute \
                curl \
                wget \
                git
            ;;
        fedora)
            dnf install -y \
                python3 \
                python3-pip \
                sudo \
                util-linux \
                iproute \
                curl \
                wget \
                git
            ;;
        *)
            warning "Unknown distribution ($DISTRO). Please install dependencies manually:"
            warning "  - Python 3.8+"
            warning "  - pip3"
            warning "  - sudo"
            warning "  - lastlog"
            warning "  - iproute2/iproute"
            warning "  - curl, wget, git"
            read -p "Continue with installation? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
            ;;
    esac
    
    success "System dependencies installed"
}

# Install Python dependencies
install_python_dependencies() {
    log "Installing Python dependencies..."
    
    # Upgrade pip
    python3 -m pip install --upgrade pip
    
    # Install requirements
    if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
        pip3 install -r "$SCRIPT_DIR/requirements.txt"
        success "Python dependencies installed"
    else
        warning "requirements.txt not found, installing basic dependencies"
        pip3 install \
            psutil \
            pyyaml \
            jinja2 \
            matplotlib \
            seaborn
    fi
}

# Create service user
create_service_user() {
    log "Creating service user..."
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
        success "Created service user: $SERVICE_USER"
    else
        warning "Service user $SERVICE_USER already exists"
    fi
}

# Install the auditor
install_auditor() {
    log "Installing Linux Server Auditor..."
    
    # Create installation directory
    mkdir -p "$INSTALL_DIR"
    
    # Copy files
    cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR"/
    
    # Set permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chmod +x "$INSTALL_DIR/main.py"
    
    # Create symlink
    ln -sf "$INSTALL_DIR/main.py" /usr/local/bin/auditor
    
    success "Linux Server Auditor installed to $INSTALL_DIR"
}

# Create systemd service (optional)
create_service() {
    read -p "Create systemd service? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Creating systemd service..."
        
        cat > /etc/systemd/system/linux-auditor.service << EOF
[Unit]
Description=Linux Server Auditor
After=network.target

[Service]
Type=oneshot
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/main.py --all --output html --report-dir /var/log/auditor
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        success "Systemd service created"
        warning "To enable automatic audits, run: systemctl enable linux-auditor"
    fi
}

# Create cron job (optional)
create_cron_job() {
    read -p "Create weekly cron job? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Creating weekly cron job..."
        
        cat > /etc/cron.weekly/linux-auditor << EOF
#!/bin/bash
# Weekly Linux Server Auditor run
cd $INSTALL_DIR
/usr/bin/python3 main.py --all --output html --report-dir /var/log/auditor --quiet
EOF
        
        chmod +x /etc/cron.weekly/linux-auditor
        success "Weekly cron job created"
    fi
}

# Create log directory
setup_logging() {
    log "Setting up logging..."
    
    mkdir -p /var/log/auditor
    chown "$SERVICE_USER:$SERVICE_USER" /var/log/auditor
    
    # Create logrotate configuration
    cat > /etc/logrotate.d/linux-auditor << EOF
/var/log/auditor/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $SERVICE_USER $SERVICE_USER
    postrotate
        # Optional: restart services if needed
    endscript
}
EOF
    
    success "Logging configured"
}

# Verify installation
verify_installation() {
    log "Verifying installation..."
    
    # Check if main script is executable
    if [ -x "/usr/local/bin/auditor" ]; then
        success "Auditor command available: /usr/local/bin/auditor"
    else
        error "Auditor command not found"
        exit 1
    fi
    
    # Test basic functionality
    if /usr/local/bin/auditor --help &>/dev/null; then
        success "Auditor help command works"
    else
        warning "Auditor help command failed - check installation"
    fi
    
    # Check Python dependencies
    python3 -c "import psutil, yaml, jinja2" 2>/dev/null && \
        success "Python dependencies available" || \
        warning "Some Python dependencies may be missing"
}

# Display post-installation instructions
show_instructions() {
    echo
    echo "=========================================="
    echo "🎉 Linux Server Auditor Installation Complete!"
    echo "=========================================="
    echo
    echo "Installation directory: $INSTALL_DIR"
    echo "Service user: $SERVICE_USER"
    echo "Log directory: /var/log/auditor"
    echo
    echo "Usage examples:"
    echo "  sudo auditor                                    # Run all modules"
    echo "  sudo auditor --modules users,security          # Run specific modules"
    echo "  sudo auditor --output html --report-dir ./     # Generate HTML report"
    echo
    echo "Configuration file: $INSTALL_DIR/config/default_config.json"
    echo
    echo "To run a test audit:"
    echo "  cd $INSTALL_DIR"
    echo "  sudo python3 main.py --quick"
    echo
    echo "For more information, see: $INSTALL_DIR/README.md"
    echo
}

# Main installation function
main() {
    echo "=========================================="
    echo "🚀 Linux Server Auditor Installation"
    echo "=========================================="
    echo
    
    check_root
    detect_distribution
    install_system_dependencies
    install_python_dependencies
    create_service_user
    install_auditor
    setup_logging
    create_service
    create_cron_job
    verify_installation
    show_instructions
}

# Handle script arguments
case "${1:-}" in
    uninstall)
        echo "Uninstall functionality not yet implemented"
        exit 1
        ;;
    --help|-h)
        echo "Linux Server Auditor Installation Script"
        echo
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  uninstall      Uninstall the auditor (not implemented)"
        exit 0
        ;;
    "")
        main
        ;;
    *)
        error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac