DOMAIN=$1

OUTPUT_FILE="$DOMAIN.waymore"

# Check if the output file already exists
if [ -f "$OUTPUT_FILE" ]; then
  echo -e "Already Scanned: $OUTPUT_FILE"
  exit 0
fi

# Run waymore if the $DOMAIN.waymore output file doesn't exist
echo "$DOMAIN" | proxychains waymore -mode U -lr 0 -xcc -oU $DOMAIN.waymore -f
cat $DOMAIN.waymore | urldedupe -s | grep -aE "=|%3D" | egrep -aiv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)" | egrep -av '/[0-9]+[-/][0-9]+[-/][0-9]+' | unew | python3 ../pvreplace-0.0.5/pvreplace.py -payload ../pvreplace-0.0.5/payloads.txt -part param-value -type postfix -mode single -without-encode | shuf | unew -q pvreplace.txt
# cat pvreplace.txt | xsschecker -match "rix4uni" -ssc 403,400 -maxssc 20 -scdn "cloudflare,AkamaiGHost,CloudFront,Imperva" -retries 1 -vuln -nc -t 100 -ao xsschecker.txt
cat pvreplace.txt | xsschecker -match "rix4uni" -ssc 403,400 -maxssc 100 -retries 1 -vuln -nc -t 100 -ao xsschecker.txt

# replace all spaces with %20 using sed 's/ /%20/g'
# cat xsschecker.txt | egrep -v "Vulnerable: \[403\]" | awk '{print $4}' | shuf | sed 's/ /%20/g' | unew -q urls.txt
# cat xsschecker.txt | egrep -v "Vulnerable: \[403\]" | sed 's/^[^ ]\+ \[[^]]\+\] \[[^]]\+\] //' | shuf  | unew -q urls.txt
cat xsschecker.txt | egrep -v "Vulnerable: \[403\]" | awk -F"]" '{gsub(/^[ \t]+/, "", $3); print $3}' | shuf  | unew -q urls.txt
rm -rf pvreplace.txt xsschecker.txt


while [ -s urls.txt ];do cat urls.txt | python3 ../xssvalidater.py -o xssvalidater-output.txt && bash ../remove-already-scanned-urls.sh xssvalidater-output.txt urls.txt;done
cat xssvalidater-output.txt | grep -E "^Vulnerable:" | sed 's/^[^ ]\+ //' | unew -q xss.txt
rm -rf urls.txt xssvalidater-output.txt

# Usage
# bash main.sh tweakimg.net


# https://anydomain.com/anynum/anynum/anynum
# cat pvreplace.txt | egrep -v 'https?://[^/]+/[0-9]+/|https?://[^/]+/[^/]+/[0-9]+/|https?://[^/]+/[^/]+/[^/]+/[0-9]+/|https?://[^/]+/[i]+/' | unew -q pvreplace2.txt