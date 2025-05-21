use super::spa_config::*;


#[derive(Debug, Clone)]
#[repr(u8)]
pub enum CspauthJobStatus {
    Created,
    Waiting,
    Started,
    Running,
    Stopped,
    Terminated,
    Finished
}

#[derive(Debug, Clone)]
pub struct CspauthTokenExpansions {
    action: String,
    option: String,
    user: String,
    sys_username: String,
    sys_uid: String,
    srcip: String,
    srcpt: String,
    ipfam: String,
    timestamp: String,
    data: String
}

#[derive(Debug, Clone)]
pub struct CspauthJob {
    command: String,
    runas: SystemUser,
    status: CspauthJobStatus,
    tokens: CspauthTokenExpansions
}

#[derive(Debug, Clone)]
pub struct CspauthRunner<'a> {
    instance: &'a SpaInstance,
    jobs: Vec<Box<CspauthJob>>
}


impl<'a> CspauthRunner<'a>
{
    pub fn exec(&mut self, job: &mut Box<CspauthJob>) -> Result<(), &'static str>
    {
        self.jobs.push(job.clone());

        Ok(())
    }
}