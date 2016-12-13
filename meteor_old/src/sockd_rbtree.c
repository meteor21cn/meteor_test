/*
 * =============================================================================
 *
 *       Filename:  rbtree.c
 *
 *    Description:  rbtree(Red-Black tree) implementation adapted from linux
 *                  kernel thus can be used in userspace c program.
 *
 *        Created:  09/02/2012 11:38:12 PM
 *
 *         Author:  Fu Haiping (forhappy), haipingf@gmail.com
 *        Company:  ICT ( Institute Of Computing Technology, CAS )
 *
 * =============================================================================
 */

/*
  Red Black Trees
  (C) 1999  Andrea Arcangeli <andrea@suse.de>
  (C) 2002  David Woodhouse <dwmw2@infradead.org>
  
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  linux/lib/rbtree.c
*/

#include <stdio.h>  
#include <stdlib.h>  
#include <string.h> 

#include "log.h" 
#include "sockd_rbtree.h" 

static int rb_node_calloc_count = 0;
static int rb_node_free_count = 0;

static void __rb_rotate_left(struct rb_node *node, struct rb_root *root)
{
	struct rb_node *right = node->rb_right;
	struct rb_node *parent = rb_parent(node);

	if ((node->rb_right = right->rb_left))
		rb_set_parent(right->rb_left, node);
	right->rb_left = node;

	rb_set_parent(right, parent);

	if (parent)
	{
		if (node == parent->rb_left)
			parent->rb_left = right;
		else
			parent->rb_right = right;
	}
	else
		root->rb_node = right;
	rb_set_parent(node, right);
}

static void __rb_rotate_right(struct rb_node *node, struct rb_root *root)
{
	struct rb_node *left = node->rb_left;
	struct rb_node *parent = rb_parent(node);

	if ((node->rb_left = left->rb_right))
		rb_set_parent(left->rb_right, node);
	left->rb_right = node;

	rb_set_parent(left, parent);

	if (parent)
	{
		if (node == parent->rb_right)
			parent->rb_right = left;
		else
			parent->rb_left = left;
	}
	else
		root->rb_node = left;
	rb_set_parent(node, left);
}

void rb_insert_color(struct rb_node *node, struct rb_root *root)
{
	struct rb_node *parent, *gparent;

	while ((parent = rb_parent(node)) && rb_is_red(parent))
	{
		gparent = rb_parent(parent);

		if (parent == gparent->rb_left)
		{
			{
				register struct rb_node *uncle = gparent->rb_right;
				if (uncle && rb_is_red(uncle))
				{
					rb_set_black(uncle);
					rb_set_black(parent);
					rb_set_red(gparent);
					node = gparent;
					continue;
				}
			}

			if (parent->rb_right == node)
			{
				register struct rb_node *tmp;
				__rb_rotate_left(parent, root);
				tmp = parent;
				parent = node;
				node = tmp;
			}

			rb_set_black(parent);
			rb_set_red(gparent);
			__rb_rotate_right(gparent, root);
		} else {
			{
				register struct rb_node *uncle = gparent->rb_left;
				if (uncle && rb_is_red(uncle))
				{
					rb_set_black(uncle);
					rb_set_black(parent);
					rb_set_red(gparent);
					node = gparent;
					continue;
				}
			}

			if (parent->rb_left == node)
			{
				register struct rb_node *tmp;
				__rb_rotate_right(parent, root);
				tmp = parent;
				parent = node;
				node = tmp;
			}

			rb_set_black(parent);
			rb_set_red(gparent);
			__rb_rotate_left(gparent, root);
		}
	}

	rb_set_black(root->rb_node);
}

static void __rb_erase_color(struct rb_node *node, struct rb_node *parent,
			     struct rb_root *root)
{
	struct rb_node *other;

	while ((!node || rb_is_black(node)) && node != root->rb_node)
	{
		if (parent->rb_left == node)
		{
			other = parent->rb_right;
			if (rb_is_red(other))
			{
				rb_set_black(other);
				rb_set_red(parent);
				__rb_rotate_left(parent, root);
				other = parent->rb_right;
			}
			if ((!other->rb_left || rb_is_black(other->rb_left)) &&
			    (!other->rb_right || rb_is_black(other->rb_right)))
			{
				rb_set_red(other);
				node = parent;
				parent = rb_parent(node);
			}
			else
			{
				if (!other->rb_right || rb_is_black(other->rb_right))
				{
					rb_set_black(other->rb_left);
					rb_set_red(other);
					__rb_rotate_right(other, root);
					other = parent->rb_right;
				}
				rb_set_color(other, rb_color(parent));
				rb_set_black(parent);
				rb_set_black(other->rb_right);
				__rb_rotate_left(parent, root);
				node = root->rb_node;
				break;
			}
		}
		else
		{
			other = parent->rb_left;
			if (rb_is_red(other))
			{
				rb_set_black(other);
				rb_set_red(parent);
				__rb_rotate_right(parent, root);
				other = parent->rb_left;
			}
			if ((!other->rb_left || rb_is_black(other->rb_left)) &&
			    (!other->rb_right || rb_is_black(other->rb_right)))
			{
				rb_set_red(other);
				node = parent;
				parent = rb_parent(node);
			}
			else
			{
				if (!other->rb_left || rb_is_black(other->rb_left))
				{
					rb_set_black(other->rb_right);
					rb_set_red(other);
					__rb_rotate_left(other, root);
					other = parent->rb_left;
				}
				rb_set_color(other, rb_color(parent));
				rb_set_black(parent);
				rb_set_black(other->rb_left);
				__rb_rotate_right(parent, root);
				node = root->rb_node;
				break;
			}
		}
	}
	if (node)
		rb_set_black(node);
}

void rb_erase(struct rb_node *node, struct rb_root *root)
{
	struct rb_node *child, *parent;
	int color;

	if (!node->rb_left)
		child = node->rb_right;
	else if (!node->rb_right)
		child = node->rb_left;
	else
	{
		struct rb_node *old = node, *left;

		node = node->rb_right;
		while ((left = node->rb_left) != NULL)
			node = left;

		if (rb_parent(old)) {
			if (rb_parent(old)->rb_left == old)
				rb_parent(old)->rb_left = node;
			else
				rb_parent(old)->rb_right = node;
		} else
			root->rb_node = node;

		child = node->rb_right;
		parent = rb_parent(node);
		color = rb_color(node);

		if (parent == old) {
			parent = node;
		} else {
			if (child)
				rb_set_parent(child, parent);
			parent->rb_left = child;

			node->rb_right = old->rb_right;
			rb_set_parent(old->rb_right, node);
		}
		//the following 2 line modified by jimmy zhou. hold no.2 bit no change
		node->rb_parent_color = ((old->rb_parent_color&~2)|rb_is_pool(node));
		//node->rb_parent_color = old->rb_parent_color;
		node->rb_left = old->rb_left;
		rb_set_parent(old->rb_left, node);

		goto color;
	}

	parent = rb_parent(node);
	color = rb_color(node);

	if (child)
		rb_set_parent(child, parent);
	if (parent)
	{
		if (parent->rb_left == node)
			parent->rb_left = child;
		else
			parent->rb_right = child;
	}
	else
		root->rb_node = child;

 color:
	if (color == RB_BLACK)
		__rb_erase_color(child, parent, root);
	root->size--;
}

static void rb_augment_path(struct rb_node *node, rb_augment_f func, void *data)
{
	struct rb_node *parent;

up:
	func(node, data);
	parent = rb_parent(node);
	if (!parent)
		return;

	if (node == parent->rb_left && parent->rb_right)
		func(parent->rb_right, data);
	else if (parent->rb_left)
		func(parent->rb_left, data);

	node = parent;
	goto up;
}

/*
 * after inserting @node into the tree, update the tree to account for
 * both the new entry and any damage done by rebalance
 */
void rb_augment_insert(struct rb_node *node, rb_augment_f func, void *data)
{
	if (node->rb_left)
		node = node->rb_left;
	else if (node->rb_right)
		node = node->rb_right;

	rb_augment_path(node, func, data);
}

/*
 * before removing the node, find the deepest node on the rebalance path
 * that will still be there after @node gets removed
 */
struct rb_node *rb_augment_erase_begin(struct rb_node *node)
{
	struct rb_node *deepest;

	if (!node->rb_right && !node->rb_left)
		deepest = rb_parent(node);
	else if (!node->rb_right)
		deepest = node->rb_left;
	else if (!node->rb_left)
		deepest = node->rb_right;
	else {
		deepest = rb_next(node);
		if (deepest->rb_right)
			deepest = deepest->rb_right;
		else if (rb_parent(deepest) != node)
			deepest = rb_parent(deepest);
	}

	return deepest;
}

/*
 * after removal, update the tree to account for the removed entry
 * and any rebalance damage.
 */
void rb_augment_erase_end(struct rb_node *node, rb_augment_f func, void *data)
{
	if (node)
		rb_augment_path(node, func, data);
}

/*
 * This function returns the first node (in sort order) of the tree.
 */
struct rb_node *rb_first(const struct rb_root *root)
{
	struct rb_node	*n;

	n = root->rb_node;
	if (!n)
		return NULL;
	while (n->rb_left)
		n = n->rb_left;
	return n;
}

struct rb_node *rb_last(const struct rb_root *root)
{
	struct rb_node	*n;

	n = root->rb_node;
	if (!n)
		return NULL;
	while (n->rb_right)
		n = n->rb_right;
	return n;
}

struct rb_node *rb_next(const struct rb_node *node)
{
	struct rb_node *parent;

	if (rb_parent(node) == node)
		return NULL;

	/* If we have a right-hand child, go down and then left as far
	   as we can. */
	if (node->rb_right) {
		node = node->rb_right; 
		while (node->rb_left)
		{
			node=node->rb_left;
		}
		return (struct rb_node *)node;
	}

	/* No right-hand children.  Everything down and left is
	   smaller than us, so any 'next' node must be in the general
	   direction of our parent. Go up the tree; any time the
	   ancestor is a right-hand child of its parent, keep going
	   up. First time it's a left-hand child of its parent, said
	   parent is our 'next' node. */
	while ((parent = rb_parent(node)) && node == parent->rb_right)
		node = parent;

	return parent;
}

struct rb_node *rb_prev(const struct rb_node *node)
{
	struct rb_node *parent;

	if (rb_parent(node) == node)
		return NULL;

	/* If we have a left-hand child, go down and then right as far
	   as we can. */
	if (node->rb_left) {
		node = node->rb_left; 
		while (node->rb_right)
			node=node->rb_right;
		return (struct rb_node *)node;
	}

	/* No left-hand children. Go up till we find an ancestor which
	   is a right-hand child of its parent */
	while ((parent = rb_parent(node)) && node == parent->rb_left)
		node = parent;

	return parent;
}

void rb_replace_node(struct rb_node *victim, struct rb_node *new,
		     struct rb_root *root)
{
	struct rb_node *parent = rb_parent(victim);

	/* Set the surrounding nodes to point to the replacement */
	if (parent) {
		if (victim == parent->rb_left)
			parent->rb_left = new;
		else
			parent->rb_right = new;
	} else {
		root->rb_node = new;
	}
	if (victim->rb_left)
		rb_set_parent(victim->rb_left, new);
	if (victim->rb_right)
		rb_set_parent(victim->rb_right, new);

	/* Copy the pointers/colour from the victim to the replacement */
	*new = *victim;
}


// -------------add by jimmy zhou
struct rb_node * _rb_node_calloc();


int rb_list_init(struct rb_list *list, int size)
{
	struct rb_node *tmp, *head, *next;
	int i;

	head = &list->head;
	rb_set_pool(head);
	rb_init_node(head);

	head->rb_left = head->rb_right = head;
	
	if( size <=0 )
		return -1;
	
	tmp = (struct rb_node *)calloc( size, sizeof(struct rb_node) );
	if( !tmp  )
		return -1;
	
	list->pool = (void *)tmp;
	for( i=0; i<size; i++ ){
		rb_set_pool(tmp);
		rb_init_node(tmp);
		next = head->rb_right;
		
		next->rb_left = tmp;
		tmp->rb_right= next;
		tmp->rb_left = head;
		head->rb_right = tmp;

		head = tmp++;
	}
	list->size = size;
	return 0;
}

// 销毁链表
int rb_list_exit(struct rb_list *list)
{
	if( !list )
		return -1;
	
	struct rb_node *head, *next, *tmp;
	head = (&list->head);
	next = head->rb_right;

	while( next != head ){
		tmp = next->rb_right;
		if( !rb_is_pool(next) ){
			rb_node_free_count++;
			free(next);
		}
		next = tmp;
	}
	
	if( list->pool )
		free(list->pool);

	return 0;
}

// 从链表中删除临时分配的节点,释放内存
int rb_list_defrag( struct rb_list *list, int size )
{
	struct rb_node *head, *next, *nright, *prev2, *next2;
	int i=0;
	
	if( rb_node_calloc_count<=rb_node_free_count )
		return rb_node_calloc_count-rb_node_free_count;
	
	head = &(list->head);
	next = head->rb_right;
	while( next != head ){
		nright = next->rb_right;
		if( !rb_is_pool(next) ){
			if( i++ >size )
				break;
			prev2 = next->rb_left;
			next2 = next->rb_right;
			
			next2->rb_left = prev2;
			prev2->rb_right = next2;
			
			rb_node_free_count++;
			list->size--;
			free(next);
		}
		next = nright;
	}
	return i;
}



// Note: can not add any same node
int rb_list_add( struct rb_list *list, struct rb_node *node)
{
	struct rb_node *head, *next;
	rb_init_node(node);
		
	head = &(list->head);
	next = head->rb_right;
	// 简单判断是否重复加入，不严谨
	if( node == next )
		return -1;
	
	next->rb_left = node;
	node->rb_right= next;
	node->rb_left = head;
	head->rb_right = node;

	list->size++;
	return 0;
}

struct rb_node *rb_list_pop(struct rb_list *list)
{
	struct rb_node *head, *next, *prev, *tmp;
	head = &(list->head);
	next = head->rb_right;
	
	// 如果链表已空，临时创建一个节点
	if( next == head ){
		tmp = _rb_node_calloc();
		return tmp;
	}

	tmp = next;
	prev = tmp->rb_left;
	next = tmp->rb_right;
	
	next->rb_left = prev;
	prev->rb_right = next;
	
	rb_init_node(tmp);
	list->size--;
	return tmp;
}


void rb_tree_init_for_long_key ( struct rb_root *root )
{
	return rb_tree_init( root, long_key_cmp );
}

void rb_tree_init_for_str_key ( struct rb_root *root )
{
	return rb_tree_init( root, str_key_cmp );
}

void rb_tree_init_for_ptr_key ( struct rb_root *root )
{
	return rb_tree_init( root, ptr_key_cmp );
}


void rb_tree_init ( struct rb_root *root, long (*key_cmp)( rb_key_t *, rb_key_t *) )
{
	root->rb_node = NULL;
	root->key_cmp = key_cmp;
	root->size=0;
}

int rb_tree_destory ( struct rb_root *root, int (*handler)(void *data) )
{
	struct rb_node *node, *next;
	
	node = rb_first( root );
	while( node ) {
		next = rb_next(node);
		if( handler )
			handler(node->data);
		if( !rb_is_pool(node) ){
			//rb_erase( node, root);  // need?
			free(node );
		}
		node = next;
	}
}


struct rb_node *rb_tree_search(struct rb_root *root, rb_key_t *key)  
{  
    struct rb_node *node = root->rb_node;  
  
    while (node) {
		long ret = root->key_cmp( key, &node->key );
	    if ( ret< 0 )  
	        node = node->rb_left;  
	    else if ( ret > 0 )  
	        node = node->rb_right;  
	    else  
	        return node;  
    }  
      
    return NULL;  
}  

struct rb_node * _rb_node_calloc()
{  
	struct rb_node *node = (struct rb_node *)malloc( sizeof(struct rb_node) );
	sys_log(LL_DEBUG, "[ %s:%d ]  rb_node_calloc_count: %d", __FILE__, __LINE__, rb_node_calloc_count );
	
	if( !node ){
		return NULL;
	}
	// for debug, look the pool is enough?
	rb_node_calloc_count++;
	rb_init_node(node);
    return node;
}

int rb_tree_insert(struct rb_root *root, rb_key_t *key, void *data, int allow_repeat )  
{  

    /* Add new node and rebalance tree. */
	struct rb_node *node = _rb_node_calloc();
	if( !node ){
		return -1;
	}
	memcpy( &node->key, key, sizeof(rb_key_t) );
	node->data = data;

    return rb_tree_insert_node( root, node, allow_repeat);
} 

int rb_tree_insert_node(struct rb_root *root, struct rb_node *node, int allow_repeat )  
{  
    struct rb_node **tmp = &(root->rb_node), *parent = NULL;  
  
    /* Figure out where to put new node */  
    while (*tmp) {  
	    parent = *tmp; 
		long ret = root->key_cmp( &(node->key), &((*tmp)->key) );
	    if( ret < 0 )  
	        tmp = &((*tmp)->rb_left);  
	    else if ( ret>0 )  
	        tmp = &((*tmp)->rb_right);  
	    else if( allow_repeat )
			tmp = &((*tmp)->rb_right);  
		else
	        return -1;
    }  
      
	rb_init_node(node);
    rb_link_node(node, parent, tmp);  
    rb_insert_color(node, root);  
    root->size++;
	
    return 0;  
} 

  
struct rb_node * rb_tree_delete(struct rb_root *root, rb_key_t *key )  
{  
    struct rb_node *node = rb_tree_search(root, key);  
    if (!node) {   
	    return NULL;  
    }  
      
    rb_erase( node, root); 
	return node;
}  

long long_key_cmp( rb_key_t *p, rb_key_t *q){
	return p->lkey - q->lkey;
}

long str_key_cmp( rb_key_t *p, rb_key_t *q){
	return (long)strcmp((unsigned char *)p->pkey, (unsigned char *)q->pkey );
}

long ptr_key_cmp( rb_key_t *p, rb_key_t *q){
	return p->pkey - q->pkey;
}

int get_rb_node_calloc_count()
{
	return rb_node_calloc_count;
}

int get_rb_node_free_count()
{
	return rb_node_free_count;
}


