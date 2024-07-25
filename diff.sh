if [ $# -ne 1 ]; then
  echo "$0 [app_name]";
  exit;
fi

cd ../linux-5.15.135/
./start.sh $1
cd -
cargo run ../linux-5.15.135/lk_trace.data | tee linux.output

cd ../lkmodel/
lktool run $1
cd -
cargo run ../lkmodel/lk_trace.data | tee lk.output

colordiff ./linux.output ./lk.output
