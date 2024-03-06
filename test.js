// const axios = require('axios')
const got = require("got");
const {SocksProxyAgent} = require("socks-proxy-agent");
const fs = require('fs')
const headers = {
'Accept': 'application/json'

};

const url = 'https://api64.ipify.org?format=json';
const httpsAgent = new SocksProxyAgent('socks5://62.178.94.31:10800')

const options = {
agent: {
https: httpsAgent,
},
};

fs.open('./input.txt','a+',function (err, fd) 
{
    if (err)
    {
        console.log(err.stack);
    }
    else 
    {
        var packetcnt = 0;
        for(var i=0; i<240; i++)
        {
            const start = process.hrtime();
            got(url, options).then( response => 
            {    
                const end = process.hrtime(start);
                var totaltime = end[0]*1000 + end[1] / 1000000;
               
                var res = "response="+response.body+" need time="+totaltime+"\n";
                fs.writeFile(fd,res, function(err)
                {
                    
                    if(err)
                    {
                        return console.log('文件写入失败！'+err.message)
                    }
                    // 若文件写入成功，将显示“文件写入成功”
                    // console.log('文件写入成功！')
                })

                }).catch(function (error) 
                {
                    const end = process.hrtime(start);
                    var totaltime = end[0]*1000 + end[1] / 1000000;
                    // var seq=i+1
                    // console.log("error="+error+" need time="+totaltime);
                    var res = "error="+error+" need time="+totaltime+"\n"
                    fs.writeFile(fd, res, function(err)
                    {
                        // 如果err为true，则文件写入失败，并返回失败信息
                        if(err)
                        {
                            return console.log('文件写入失败！'+err.message)
                        }
                        // 若文件写入成功，将显示“文件写入成功”
                        // console.log('文件写入成功！')
                    })
                    // console.log()
                })
        }
    }
})