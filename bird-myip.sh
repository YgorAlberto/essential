curl -s https://meuip.com.br | grep "Meu ip" > .meuip
cat .meuip | cut -d " " -f 8 > ip.txt
sed -i 's/<\/h3>/ /g' ip.txt
cat ip.txt
rm .meuip
rm ip.txt
