(function(){
    /* ── Page-specific setup (re-run after each turbo swap) ── */
    function initPage(){
        // Line number highlighting
        function clearHL(){
            document.querySelectorAll('.code-table tr.highlighted').forEach(function(r){r.classList.remove('highlighted')});
        }
        function applyHash(){
            clearHL();
            var h=location.hash.replace('#','');
            if(!h)return;
            var m=h.match(/^L(\d+)(?:-L(\d+))?$/);
            if(!m)return;
            var s=parseInt(m[1],10),e=m[2]?parseInt(m[2],10):s;
            if(s>e){var t=s;s=e;e=t;}
            for(var i=s;i<=e;i++){
                var row=document.getElementById('L'+i);
                if(row)row.classList.add('highlighted');
            }
            var first=document.getElementById('L'+s);
            if(first)first.scrollIntoView({block:'center'});
        }
        document.querySelectorAll('.line-number').forEach(function(td){
            td.style.cursor='pointer';
            td.addEventListener('click',function(){
                location.hash='L'+this.dataset.line;
            });
        });
        window.removeEventListener('hashchange',applyHash);
        window.addEventListener('hashchange',applyHash);
        applyHash();
        // Copy button
        window.copyFileContent=function(){
            var tpl=document.getElementById('raw-content');
            if(!tpl)return;
            var text=tpl.content?tpl.content.textContent:tpl.innerHTML;
            navigator.clipboard.writeText(text).then(function(){
                var btn=document.querySelector('.copy-btn');
                if(btn){btn.textContent='Copied!';setTimeout(function(){btn.textContent='Copy'},2000);}
            });
        };
    }

    /* ── Turbo navigation ── */
    var bar=document.getElementById('turbo-bar');
    var parser=new DOMParser();

    function showBar(){bar.classList.add('loading');}
    function hideBar(){bar.classList.remove('loading');bar.classList.add('done');setTimeout(function(){bar.classList.remove('done')},300);}

    function turboNavigate(url,pushState){
        showBar();
        fetch(url,{headers:{'Accept':'text/html'}}).then(function(r){return r.text()}).then(function(html){
            var doc=parser.parseFromString(html,'text/html');
            var newMain=doc.querySelector('main');
            var newHeader=doc.querySelector('header');
            var newTitle=doc.querySelector('title');
            if(newMain){
                var main=document.querySelector('main');
                main.style.opacity='0';
                setTimeout(function(){
                    main.innerHTML=newMain.innerHTML;
                    main.style.opacity='';
                    if(newHeader)document.querySelector('header').innerHTML=newHeader.innerHTML;
                    if(newTitle)document.title=newTitle.textContent;
                    if(pushState)history.pushState({turbo:true,url:url},'',url);
                    window.scrollTo(0,0);
                    hideBar();
                    initPage();
                },80);
            }
        }).catch(function(){
            hideBar();
            location.href=url;
        });
    }

    document.addEventListener('click',function(e){
        var a=e.target.closest('a');
        if(!a)return;
        var href=a.getAttribute('href');
        if(!href||href.charAt(0)!=='/'||a.hasAttribute('download'))return;
        if(href.indexOf('data:')===0)return;
        e.preventDefault();
        turboNavigate(href,true);
    });

    window.addEventListener('popstate',function(e){
        if(e.state&&e.state.turbo){
            turboNavigate(e.state.url,false);
        }
    });

    // Seed initial history entry
    history.replaceState({turbo:true,url:location.href},'',location.href);

    initPage();
})();
