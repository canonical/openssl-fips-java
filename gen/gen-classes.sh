#
#  Copyright (C) Canonical, Ltd.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 3.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
while IFS= read -r line
do 
  ks=$(echo $line | cut -d'-' -f2)
  mode=$(echo $line | cut -d'-' -f3)
  while IFS= read -r line
  do
    pad=$line
    pad_c=$(echo $pad | tr "." _ | tr "-" _)
    path=${PWD}/src/main/java/com/canonical/openssl/cipher/AES${ks}with${mode}padding${pad_c}.java
    cp ${PWD}/gen/template.java ${path}
    sed -i 's/__PADC__/'$pad_c'/g' ${path}
    sed -i 's/__KS__/'$ks'/g' ${path} 
    sed -i 's/__MODE__/'$mode'/g' ${path} 
    sed -i 's/__PAD__/'$pad'/g' ${path} 
  done <${PWD}/gen/padding.txt
done <${PWD}/gen/name-key-size-mode.txt
