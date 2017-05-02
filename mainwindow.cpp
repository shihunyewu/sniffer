#include "mainwindow.h"

MainWindow::MainWindow()
{
}

void MainWindow::sleep( int minsec)
{
    QTime t;
    t.start();
    while(t.elapsed()<minsec)
        QCoreApplication::processEvents();
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    int res = this->isToContinue();
    if (res == QMessageBox::Yes) {
        save();
        writeSettings();
        event->accept();
    } else if (res == QMessageBox::No){
        writeSettings();
        event->accept();
    } else if (res == QMessageBox::Cancel){
        event->ignore();
    }
}


void MainWindow::writeSettings()
{
    QSettings settings("Sniffer.ini", QSettings::IniFormat);

    settings.setValue("iOpenDevNum", settingInfo->iOpenDevNum);
    settings.setValue("bPromiscuous", settingInfo->bPromiscuous);
    settings.setValue("bAutoBegin", settingInfo->bAutoBegin);
}

void MainWindow::save()
{
    QString fileName = QFileDialog::getSaveFileName(this,
                            tr("另存为 ..."), ".",
                            tr("Sniffer 捕获数据文件 (*.sni)"));

    if (!fileName.isEmpty()) {
        saveFile(fileName);
    }
}

int MainWindow::isToContinue()
{
    if (mainTreeView->isChanged()) {
        return QMessageBox::question(NULL, tr("Sniffer"),
                        tr("<H3>看起来我们似乎已经捕获到了一些数据。</H3>"
                            "您需要保存这些捕获的数据供以后分析使用吗？"),
                        QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel);
    }
    return QMessageBox::No;
}

bool MainWindow::saveFile(const QString &fileName)
{
    if (curFile.isEmpty()) {
        return false;
    }

    if(!QFile::copy(curFile, fileName)) {
        QMessageBox::warning(this, tr("Sniffer"),
                        tr("<H3>文件保存失败。</H3>很遗憾遇到这样的事情，"
                                    "您是否选择了一个没有权限覆盖的文件？"), QMessageBox::Ok);
        return false;
    }

    setCurrentFile(fileName);
    statusBar()->showMessage(tr("File saved"), 2000);

    return true;
}
