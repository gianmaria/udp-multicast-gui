#include "mainwindow.h"

#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QWidget>
#include <QLabel>
#include <QMessageBox> // For error messages
#include <QNetworkInterface> // Potentially needed for multicast interface selection (advanced)
#include <QScrollBar> // To auto-scroll the text edit

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setupUi();
}

MainWindow::~MainWindow()
{
    // While parent ownership handles deletion, explicit cleanup is good practice
    closeSocket();
    // Qt's parent-child mechanism will delete UI elements automatically
}

void MainWindow::setupUi()
{
    setWindowTitle(tr("Multicast UDP Receiver"));
    resize(600, 400); // Set a reasonable default size

    centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    mainLayout = new QVBoxLayout(centralWidget);

    // --- Message Display ---
    messageDisplay = new QTextEdit(centralWidget);
    messageDisplay->setReadOnly(true); // User shouldn't edit received messages
    messageDisplay->setFontFamily("Consolas"); // Monospaced font is good for hex
    mainLayout->addWidget(messageDisplay);

    // --- Bottom Controls Area ---
    bottomWidget = new QWidget(centralWidget);
    bottomLayout = new QHBoxLayout(bottomWidget);
    bottomLayout->setContentsMargins(0, 5, 0, 0); // Add some top margin

    ipLabel = new QLabel(tr("IP:"), bottomWidget);
    ipLineEdit = new QLineEdit(bottomWidget);
    ipLineEdit->setPlaceholderText(tr("Multicast IP (e.g., 239.255.0.1)"));

    portLabel = new QLabel(tr("Port:"), bottomWidget);
    portLineEdit = new QLineEdit(bottomWidget);
    portLineEdit->setPlaceholderText(tr("Port (e.g., 5000)"));
    // Optional: Add validator for port number
    // portLineEdit->setValidator(new QIntValidator(1, 65535, this));

    connectButton = new QPushButton(tr("Connect"), bottomWidget);

    bottomLayout->addWidget(ipLabel);
    bottomLayout->addWidget(ipLineEdit, 1); // Stretch IP field
    bottomLayout->addWidget(portLabel);
    bottomLayout->addWidget(portLineEdit, 0); // Fixed size port field
    bottomLayout->addWidget(connectButton);

    mainLayout->addWidget(bottomWidget); // Add bottom row to main layout

    // --- Connections ---
    connect(connectButton, &QPushButton::clicked, this, &MainWindow::onConnectButtonClicked);

    // Set initial state (optional, but good practice)
    logMessage("Enter Multicast IP and Port, then click Connect.");

    ipLineEdit->setText("225.0.0.38");
    portLineEdit->setText("6655");
}

void MainWindow::onConnectButtonClicked()
{
    // --- Get and Validate Input ---
    QString ipString = ipLineEdit->text().trimmed();
    QString portString = portLineEdit->text().trimmed();

    if (ipString.isEmpty() || portString.isEmpty()) {
        QMessageBox::warning(this, tr("Input Error"), tr("IP address and Port cannot be empty."));
        return;
    }

    bool portOk;
    quint16 port = portString.toUShort(&portOk); // quint16 is standard for ports
    if (!portOk || port == 0) {
        QMessageBox::warning(this, tr("Input Error"), tr("Invalid Port number. Please enter a value between 1 and 65535."));
        return;
    }

    QHostAddress groupAddress(ipString);
    if (groupAddress.isNull() || !groupAddress.isMulticast()) {
        QMessageBox::warning(this, tr("Input Error"), tr("Invalid Multicast IP address."));
        return;
    }

    // --- Close existing socket if trying to reconnect ---
    closeSocket(); // Ensure previous connection is terminated

    // --- Create and Configure Socket ---
    udpSocket = new QUdpSocket(this); // Set parent for auto-deletion

    // Connect the readyRead signal *before* binding
    connect(udpSocket, &QUdpSocket::readyRead, this, &MainWindow::readPendingDatagrams);

    // --- Bind Socket ---
    // Bind to AnyIPv4 address and the specified port.
    // ShareAddress allows multiple sockets to bind to the same address/port (essential for multicast).
    // ReuseAddressHint is often helpful as well.

    // QHostAddress::AnyIPv4
    // QHostAddress("10.11.81.21")

    if (!udpSocket->bind(QHostAddress::AnyIPv4, port, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint)) {
        QString errorMsg = tr("Failed to bind to port %1: %2").arg(port).arg(udpSocket->errorString());
        QMessageBox::critical(this, tr("Socket Error"), errorMsg);
        logMessage(QString("Error: %1").arg(errorMsg));
        closeSocket(); // Clean up failed socket
        return;
    }
    logMessage(QString("Socket bound to port %1.").arg(port));

    // --- Join Multicast Group ---
    if (!udpSocket->joinMulticastGroup(groupAddress)) {
        QString errorMsg = tr("Failed to join multicast group %1: %2").arg(groupAddress.toString()).arg(udpSocket->errorString());
        QMessageBox::critical(this, tr("Socket Error"), errorMsg);
        logMessage(QString("Error: %1").arg(errorMsg));
        closeSocket(); // Clean up failed socket
        return;
    }

    // --- Success ---
    currentGroupAddress = groupAddress;
    currentPort = port;

    logMessage(QString("Successfully joined multicast group %1 on port %2.")
                   .arg(currentGroupAddress.toString())
                   .arg(currentPort));

    // Update UI state (optional: disable inputs after connecting)
    ipLineEdit->setEnabled(false);
    portLineEdit->setEnabled(false);
    connectButton->setText(tr("Disconnect")); // Change button text
    // Re-route button click (or handle state internally)
    disconnect(connectButton, &QPushButton::clicked, this, &MainWindow::onConnectButtonClicked);
    connect(connectButton, &QPushButton::clicked, this, &MainWindow::closeSocket); // Now button disconnects

    messageDisplay->clear(); // Clear previous messages on new connection
}


void MainWindow::readPendingDatagrams()
{
    if (!udpSocket) return;

    while (udpSocket->hasPendingDatagrams())
    {
        QByteArray datagram;
        // Resize byte array to fit the incoming datagram
        datagram.resize(static_cast<int>(udpSocket->pendingDatagramSize()));
        QHostAddress senderAddress;
        quint16 senderPort;

        qint64 bytesRead = udpSocket->readDatagram(datagram.data(), datagram.size(),
                                                   &senderAddress, &senderPort);

        if (bytesRead > 0) {
            // Convert data to hex string with spaces between bytes
            QString hexString = QString::fromLatin1(datagram.toHex(' '));

            // Format the output message
            QString logEntry = QString("[%1:%2] Received %3 bytes:\n%4\n")
                .arg(senderAddress.toString()) // Show sender info
                .arg(senderPort)
                .arg(bytesRead)
                .arg(hexString);

            logMessage(logEntry);
        } else if (bytesRead == -1) {
            logMessage(QString("Error reading datagram: %1").arg(udpSocket->errorString()));
            // Decide if the error is fatal and requires closing the socket
            // For transient errors, you might just log them.
        }
    }
}

void MainWindow::closeSocket()
{
    if (udpSocket) {
        // Leave the multicast group cleanly
        if (!currentGroupAddress.isNull()) {
            udpSocket->leaveMulticastGroup(currentGroupAddress);
            logMessage(QString("Left multicast group %1.").arg(currentGroupAddress.toString()));
        }

        udpSocket->close(); // Close the socket
        udpSocket->deleteLater(); // Schedule deletion safely
        udpSocket = nullptr;
        currentGroupAddress = QHostAddress();
        currentPort = 0;

        logMessage("Socket disconnected.");

        // Reset UI state
        ipLineEdit->setEnabled(true);
        portLineEdit->setEnabled(true);
        connectButton->setText(tr("Connect"));

        // Disconnect the "Disconnect" action and reconnect the "Connect" action
        disconnect(connectButton, &QPushButton::clicked, this, &MainWindow::closeSocket);
        connect(connectButton, &QPushButton::clicked, this, &MainWindow::onConnectButtonClicked);
    }
}

void MainWindow::logMessage(const QString& message)
{
    messageDisplay->append(message);
    // Auto-scroll to the bottom
    messageDisplay->verticalScrollBar()->setValue(messageDisplay->verticalScrollBar()->maximum());
}
