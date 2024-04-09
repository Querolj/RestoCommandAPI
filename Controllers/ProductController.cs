using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RestoCommand.Models;
using RestoCommandAPI.Authentication;
using RestoCommandAPI.Database;

namespace RestoCommandAPI.Controllers
{
    [Route("api/[controller]")]
    public class ProductController : ControllerBase
    {

        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public ProductController(ApplicationDbContext context, RoleManager<IdentityRole> roleManager, IConfiguration configuration, UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _roleManager = roleManager;
            _userManager = userManager;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("add")]
        public async Task<ActionResult<Product>> PostProduct(Product product)
        {
            if (product == null)
            {
                return BadRequest("Could not post product, " + nameof(product) + " is null");
            }

            _context.Product.Add(product);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(PostProduct), new { id = product.Id }, product);
        }

        [HttpGet("get/{id}")]
        public async Task<ActionResult<Product>> GetProduct(string id)
        {
            Product? product = await _context.Product.FindAsync(id);

            if (product == null)
            {
                return NotFound("Product with id " + id + " not found");
            }

            return product;
        }

        [HttpGet("getAll")]
        public async Task<ActionResult<List<Product>>> GetProducts()
        {
            List<Product> products = await _context.Product.ToListAsync();

            return products;
        }

        [HttpPut("edit/{id}")]
        public async Task<IActionResult> PutProduct(string id, Product product)
        {
            if (id != product.Id)
            {
                return BadRequest("Product id does not match");
            }

            try
            {
                Product? productToChange = await _context.Product.FindAsync(id);

                //Product? productToChange = _context.Product.Find(id);
                if (productToChange == null)
                {
                    return NotFound("Product with id " + id + " not found 1");
                }

                productToChange.Copy(product);
                _context.Product.Update(productToChange);
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException e)
            {
                if (!ProductExists(id))
                {
                    return NotFound("Product with id " + id + " not found : \n" + e);
                }
                else
                {
                    throw;
                }
            }

            return Ok();
        }

        private bool ProductExists(string id)
        {
            return _context.Product.Any(e => e.Id == id);
        }

        // POST: Product/Delete/5
        [HttpDelete("delete/{id}")]
        public async Task<IActionResult> Delete(string id)
        {
            var product = await _context.Product.FindAsync(id);
            if (product != null)
            {
                _context.Product.Remove(product);
            }
            else
            {
                return NotFound("Product with id " + id + " not found");
            }

            await _context.SaveChangesAsync();
            return Ok();
        }

    }
}
