function twoNumberFind(arr, objetivo){
    for(let i = 0; i < arr.length; i++){
        for(let j  = i + 1; j < arr.length; j++){
            if(arr[i] + arr[j] === objetivo){
                return [arr[i], arr[j]]
            }
        }
    }
    return null
}

let number = [1,2,3,4,5,6,7,8,9]
let obej = 14
console.log(twoNumberFind(number, obej))