using DMS.Models;
//using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace DMS.Data
{
    public class DemoTokenContext : IdentityDbContext
    {
        public DemoTokenContext(DbContextOptions<DemoTokenContext> options)
            : base(options)
        {

        }

    }
}
