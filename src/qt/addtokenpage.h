#ifndef ADDTOKENPAGE_H
#define ADDTOKENPAGE_H

#include <QWidget>
class Token;

namespace Ui {
class AddTokenPage;
}

class AddTokenPage : public QWidget
{
    Q_OBJECT

public:
    explicit AddTokenPage(QWidget *parent = 0);
    ~AddTokenPage();
    void clearAll();

private Q_SLOTS:
    void on_clearButton_clicked();
    void on_confirmButton_clicked();
    void on_addressChanged();

Q_SIGNALS:
    void on_addNewToken(QString _address, QString _name, QString _symbol, int _decimals, double _balance);

private:
    Ui::AddTokenPage *ui;
    Token *m_tokenABI;
};

#endif // ADDTOKENPAGE_H