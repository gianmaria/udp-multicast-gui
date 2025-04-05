#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtNetwork/QUdpSocket> // Include for QUdpSocket
#include <QHostAddress>        // Include for QHostAddress

// Forward declarations to reduce header includes
class QTextEdit;
class QLineEdit;
class QPushButton;
class QVBoxLayout;
class QHBoxLayout;
class QWidget;
class QLabel; // For labels next to LineEdits

class MainWindow : public QMainWindow
{
    Q_OBJECT // Essential for signals/slots

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override; // Use override for virtual destructors

private slots:
    void onConnectButtonClicked();
    void readPendingDatagrams();

private:
    void setupUi();
    void logMessage(const QString& message);
    void closeSocket(); // Helper to clean up the socket

    // --- UI Elements ---
    QWidget*     centralWidget = nullptr;
    QVBoxLayout* mainLayout = nullptr;
    QTextEdit*   messageDisplay = nullptr;
    QWidget*     bottomWidget = nullptr; // Widget to hold bottom controls
    QHBoxLayout* bottomLayout = nullptr;
    QLabel*      ipLabel = nullptr;
    QLineEdit*   ipLineEdit = nullptr;
    QLabel*      portLabel = nullptr;
    QLineEdit*   portLineEdit = nullptr;
    QPushButton* connectButton = nullptr;

    // --- Networking ---
    QUdpSocket*  udpSocket = nullptr;
    QHostAddress currentGroupAddress;
    quint16      currentPort = 0;
};

#endif // MAINWINDOW_H