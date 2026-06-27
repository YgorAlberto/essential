#FERRAMENTA PARA ATUALIZAR COMPLETAMENTE O SISTEMA OPERACIONAL APT
sudo apt --fix-broken install -y
sudo apt update && sudo apt full-upgrade -y && sudo apt autoremove -y
echo " "
echo "============"
echo "===DE=NOVO=="
echo "============"
echo " "
sudo apt --fix-broken install -y
sudo apt-get update && sudo apt-get full-upgrade -y && sudo apt-get autoremove -y
