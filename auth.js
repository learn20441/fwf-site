window.AUTH = {
  async api(url, opts={}){
    const res = await fetch(url, {
      method: opts.method||'GET',
      headers: {'Content-Type':'application/json'},
      body: opts.body?JSON.stringify(opts.body):undefined,
      credentials: 'include'
    });
    if(!res.ok){
      const err = await res.json().catch(()=>({error:'Error'}));
      throw new Error(err.error||'Request failed');
    }
    return res.json();
  }
};
