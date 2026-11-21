
(function(){
  var active={}, kind='', query='';
  document.querySelectorAll('.chip[data-verdict]').forEach(function(c){
    active[c.dataset.verdict]=c.getAttribute('aria-pressed')==='true';
    c.addEventListener('click',function(){
      active[c.dataset.verdict]=!active[c.dataset.verdict];
      c.setAttribute('aria-pressed',active[c.dataset.verdict]);apply();});
  });
  var search=document.getElementById('q'), select=document.getElementById('kind');
  if(search)search.addEventListener('input',function(){query=search.value.toLowerCase().trim();apply();});
  if(select)select.addEventListener('change',function(){kind=select.value;apply();});
  function apply(){
    var shown=0;
    document.querySelectorAll('[data-verdict].row').forEach(function(el){
      var ok=active[el.dataset.verdict]!==false&&(!kind||el.dataset.kind===kind)
        &&(!query||el.dataset.text.indexOf(query)!==-1);
      el.classList.toggle('hidden',!ok);if(ok)shown++;
    });
    document.querySelectorAll('section[data-section]').forEach(function(s){
      s.classList.toggle('hidden',!s.querySelector('.row:not(.hidden)'));
    });
    var counter=document.getElementById('shown');if(counter)counter.textContent=shown;
  }
  document.addEventListener('click',function(ev){
    var b=ev.target.closest('.copy');if(!b)return;
    var text=b.parentNode.querySelector('pre').textContent;
    function done(){var o=b.textContent;b.textContent='Copied';setTimeout(function(){b.textContent=o;},1200);}
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(done,fallback);}
    else fallback();
    function fallback(){var t=document.createElement('textarea');t.value=text;document.body.appendChild(t);
      t.select();try{document.execCommand('copy');done();}catch(e){}document.body.removeChild(t);}
  });
  apply();
})();
