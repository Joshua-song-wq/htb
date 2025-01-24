var a = 'abc';//throughout program
let b = `def`;//inside scope
const pi = 3.14;
console.log(b[b.length-1]);//f

var obj = {'hat':'myhat','socks':'mysocks'}
delete obj.hat;//delete hat property
console.log(obj.hat) // undefined
function(a,b){
  if(a==b) // without type{
    return a-b;}
  else if(a===b) // check type{
  return a+b;}
}
